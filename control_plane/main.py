#!/usr/bin/env python3
"""NetShield control plane: spawn and supervise the C++ node fleet."""

from __future__ import annotations

import json
import signal
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path

REPO_ROOT: Path = Path(__file__).resolve().parent.parent
NODE_BINARY: Path = REPO_ROOT / "bin" / "node"
TOPOLOGY_PATH: Path = REPO_ROOT / "config" / "topology.json"
SHUTDOWN_GRACE_SECONDS: float = 5.0


@dataclass(frozen=True)
class NodeConfig:
    id: int
    port: int
    role: str


@dataclass(frozen=True)
class Edge:
    src: int
    dst: int


@dataclass(frozen=True)
class Topology:
    nodes: list[NodeConfig]
    edges: list[Edge]


def load_topology(path: Path) -> Topology:
    with path.open(encoding="utf-8") as f:
        raw = json.load(f)
    nodes = [
        NodeConfig(id=n["id"], port=n["port"], role=n["role"])
        for n in raw["nodes"]
    ]
    edges = [Edge(src=e["from"], dst=e["to"]) for e in raw["edges"]]
    return Topology(nodes=nodes, edges=edges)


def spawn_node(node: NodeConfig, binary: Path) -> subprocess.Popen[bytes]:
    # start_new_session=True calls setsid() in the child after fork, placing
    # it in its own process group. Without this, a terminal Ctrl+C broadcasts
    # SIGINT to every member of the foreground group and the children would
    # die before this control plane could orchestrate the shutdown.
    return subprocess.Popen(
        [str(binary), str(node.port)],
        start_new_session=True,
    )


def shutdown(
    processes: list[tuple[NodeConfig, subprocess.Popen[bytes]]],
    grace: float = SHUTDOWN_GRACE_SECONDS,
) -> None:
    live = [(n, p) for n, p in processes if p.poll() is None]
    if not live:
        print("[ctl] no live nodes to shut down", flush=True)
        return

    print(f"[ctl] sending SIGTERM to {len(live)} nodes...", flush=True)
    for _, proc in live:
        proc.terminate()

    deadline = time.monotonic() + grace
    pending = list(live)
    while pending and time.monotonic() < deadline:
        still_running: list[tuple[NodeConfig, subprocess.Popen[bytes]]] = []
        for node, proc in pending:
            if proc.poll() is None:
                still_running.append((node, proc))
            else:
                print(
                    f"[ctl] node id={node.id} pid={proc.pid} "
                    f"exited rc={proc.returncode}",
                    flush=True,
                )
        pending = still_running
        if pending:
            time.sleep(0.05)

    # Escalate any survivors of the grace window. SIGKILL is uncatchable, so
    # this both guarantees termination and reaps the PID via the wait() call.
    for node, proc in pending:
        print(
            f"[ctl] node id={node.id} pid={proc.pid} did not exit within "
            f"{grace}s — sending SIGKILL",
            flush=True,
        )
        proc.kill()
        proc.wait()


def main() -> int:
    if not NODE_BINARY.exists():
        print(
            f"[ctl] node binary not found at {NODE_BINARY}\n"
            f"      build first: g++ -std=c++17 -Wall -Wextra -pthread "
            f"src/node.cpp -o bin/node",
            file=sys.stderr,
        )
        return 1

    topology = load_topology(TOPOLOGY_PATH)
    print(
        f"[ctl] loaded topology: {len(topology.nodes)} nodes, "
        f"{len(topology.edges)} edges",
        flush=True,
    )

    processes: list[tuple[NodeConfig, subprocess.Popen[bytes]]] = []
    try:
        for node in topology.nodes:
            proc = spawn_node(node, NODE_BINARY)
            processes.append((node, proc))
            print(
                f"[ctl] spawned id={node.id} role={node.role:<4} "
                f"port={node.port} pid={proc.pid}",
                flush=True,
            )

        print(
            f"[ctl] all {len(processes)} nodes running. "
            f"Press Ctrl+C to stop.",
            flush=True,
        )
        # signal.pause() blocks until any signal is delivered. SIGINT raises
        # KeyboardInterrupt, which we handle below; any other signal simply
        # returns and proceeds to the orderly shutdown in finally.
        signal.pause()
    except KeyboardInterrupt:
        print("\n[ctl] received SIGINT — initiating graceful shutdown",
              flush=True)
    finally:
        shutdown(processes)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
