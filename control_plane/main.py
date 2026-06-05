#!/usr/bin/env python3
"""NetShield control plane: spawn, supervise, and visualize the C++ node fleet."""

from __future__ import annotations

import json
import signal
import socket
import struct
import subprocess
import sys
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from types import FrameType
from typing import IO

REPO_ROOT: Path = Path(__file__).resolve().parent.parent
NODE_BINARY: Path = REPO_ROOT / "bin" / "node"
TOPOLOGY_PATH: Path = REPO_ROOT / "config" / "topology.json"
LOG_DIR: Path = Path("/tmp/netshield")
SHUTDOWN_GRACE_SECONDS: float = 5.0
TELEMETRY_PORT: int = 9000
DASHBOARD_REFRESH_SECONDS: float = 2.0
HEARTBEAT_STALE_SECONDS: float = 3.0

# Wire format — mirrors src/packet.h. Must stay in sync with the C++ side.
PACKET_FMT: str = "!IHHBH512s"
PACKET_SIZE: int = struct.calcsize(PACKET_FMT)
PACKET_TYPE_HEARTBEAT: int = 2

# ANSI escapes. Used for clear-screen and stale-cell highlighting in the
# dashboard. Auto-suppressed when stdout is not a TTY.
_USE_COLOR: bool = sys.stdout.isatty()
_CLEAR_SCREEN: str = "\033[H\033[2J" if _USE_COLOR else ""
_RED: str = "\033[31m" if _USE_COLOR else ""
_GREEN: str = "\033[32m" if _USE_COLOR else ""
_YELLOW: str = "\033[33m" if _USE_COLOR else ""
_DIM: str = "\033[2m" if _USE_COLOR else ""
_RESET: str = "\033[0m" if _USE_COLOR else ""


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


@dataclass
class Heartbeat:
    node_id: int
    queue_size: int
    delivered: int
    forwarded: int
    dropped: int
    received_at: float  # time.monotonic() at receipt


@dataclass
class SpawnedNode:
    config: NodeConfig
    process: subprocess.Popen[bytes]
    log_file: IO[str]


def load_topology(path: Path) -> Topology:
    with path.open(encoding="utf-8") as f:
        raw = json.load(f)
    nodes = [
        NodeConfig(id=n["id"], port=n["port"], role=n["role"])
        for n in raw["nodes"]
    ]
    edges = [Edge(src=e["from"], dst=e["to"]) for e in raw["edges"]]
    return Topology(nodes=nodes, edges=edges)


def spawn_node(
    node: NodeConfig,
    binary: Path,
    topology_path: Path,
    telemetry_port: int,
    log_dir: Path,
) -> SpawnedNode:
    log_path = log_dir / f"node-{node.id}.log"
    log_file = log_path.open("w", encoding="utf-8")
    # start_new_session=True isolates the child in its own session so a
    # terminal SIGINT is delivered only to this supervisor, never broadcast
    # to the foreground process group.
    proc = subprocess.Popen(
        [str(binary), str(node.id), str(topology_path), str(telemetry_port)],
        stdout=log_file,
        stderr=subprocess.STDOUT,
        start_new_session=True,
    )
    return SpawnedNode(config=node, process=proc, log_file=log_file)


def _parse_heartbeat(data: bytes) -> Heartbeat | None:
    if len(data) != PACKET_SIZE:
        return None
    try:
        _pid, src, _dst, ptype, payload_len, payload = struct.unpack(
            PACKET_FMT, data
        )
    except struct.error:
        return None
    if ptype != PACKET_TYPE_HEARTBEAT or payload_len > 512:
        return None
    text = payload[:payload_len].decode("utf-8", errors="replace")
    try:
        fields = dict(p.split("=", 1) for p in text.split() if "=" in p)
        return Heartbeat(
            node_id=src,
            queue_size=int(fields["queue"]),
            delivered=int(fields["delivered"]),
            forwarded=int(fields["forwarded"]),
            dropped=int(fields["dropped"]),
            received_at=time.monotonic(),
        )
    except (KeyError, ValueError):
        return None


class TelemetryReceiver:
    """Background UDP listener; updates a lock-protected per-node heartbeat map."""

    def __init__(self, port: int) -> None:
        self.port = port
        self._heartbeats: dict[int, Heartbeat] = {}
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind(("127.0.0.1", port))
        # Periodic timeout lets the loop notice _stop without needing a
        # wake-up datagram or socket.shutdown().
        self._sock.settimeout(0.5)
        self._thread = threading.Thread(
            target=self._loop, daemon=True, name="telemetry-rx"
        )

    def start(self) -> None:
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        try:
            self._sock.close()
        except OSError:
            pass

    def snapshot(self) -> dict[int, Heartbeat]:
        with self._lock:
            return dict(self._heartbeats)

    def _loop(self) -> None:
        while not self._stop.is_set():
            try:
                data, _ = self._sock.recvfrom(2048)
            except socket.timeout:
                continue
            except OSError:
                break
            hb = _parse_heartbeat(data)
            if hb is not None:
                with self._lock:
                    self._heartbeats[hb.node_id] = hb


def render_dashboard(
    topology: Topology,
    nodes: list[SpawnedNode],
    telemetry: TelemetryReceiver,
) -> None:
    sys.stdout.write(_CLEAR_SCREEN)
    snap = telemetry.snapshot()
    now = time.monotonic()

    print("NetShield Control Plane")
    print(
        f"  topology: {len(topology.nodes)} nodes, {len(topology.edges)} edges"
        f"   |   telemetry: udp/{telemetry.port}"
        f"   |   refresh: {DASHBOARD_REFRESH_SECONDS:.0f}s"
    )
    print("-" * 84)
    print(
        f"  {'ID':>2}  {'Role':<5} {'Port':>5} {'PID':>6}   "
        f"{'Queue':>6} {'Delivered':>10} {'Forwarded':>10} {'Dropped':>8}   "
        f"{'Last HB':>10}"
    )
    print("-" * 84)

    for sn in nodes:
        hb = snap.get(sn.config.id)
        if hb is None:
            queue_s = delivered_s = forwarded_s = dropped_s = "-"
            hb_cell = f"{_YELLOW}no data{_RESET}"
        else:
            queue_s = str(hb.queue_size)
            delivered_s = str(hb.delivered)
            forwarded_s = str(hb.forwarded)
            dropped_s = str(hb.dropped)
            age = now - hb.received_at
            if age > HEARTBEAT_STALE_SECONDS:
                hb_cell = f"{_RED}{age:.1f}s STALE{_RESET}"
            else:
                hb_cell = f"{_GREEN}{age:.1f}s{_RESET}"

        rc = sn.process.poll()
        proc_state = f"  {_RED}[exited rc={rc}]{_RESET}" if rc is not None else ""

        print(
            f"  {sn.config.id:>2}  {sn.config.role:<5} {sn.config.port:>5} "
            f"{sn.process.pid:>6}   {queue_s:>6} {delivered_s:>10} "
            f"{forwarded_s:>10} {dropped_s:>8}   {hb_cell:>10}{proc_state}"
        )

    print("-" * 84)
    print(f"  {_DIM}per-node logs: {LOG_DIR}/node-N.log   |   Ctrl+C to stop{_RESET}")
    sys.stdout.flush()


def shutdown(
    nodes: list[SpawnedNode], grace: float = SHUTDOWN_GRACE_SECONDS
) -> None:
    live = [sn for sn in nodes if sn.process.poll() is None]
    if live:
        print(f"[ctl] sending SIGTERM to {len(live)} nodes...", flush=True)
        for sn in live:
            sn.process.terminate()

        deadline = time.monotonic() + grace
        pending = list(live)
        while pending and time.monotonic() < deadline:
            still_running: list[SpawnedNode] = []
            for sn in pending:
                if sn.process.poll() is None:
                    still_running.append(sn)
                else:
                    print(
                        f"[ctl] node id={sn.config.id} pid={sn.process.pid} "
                        f"exited rc={sn.process.returncode}",
                        flush=True,
                    )
            pending = still_running
            if pending:
                time.sleep(0.05)

        for sn in pending:
            print(
                f"[ctl] node id={sn.config.id} pid={sn.process.pid} did not "
                f"exit within {grace}s — sending SIGKILL",
                flush=True,
            )
            sn.process.kill()
            sn.process.wait()

    for sn in nodes:
        try:
            sn.log_file.close()
        except OSError:
            pass


_shutdown_event: threading.Event = threading.Event()


def _handle_signal(signum: int, _frame: FrameType | None) -> None:
    # Explicit handler — Python's default KeyboardInterrupt path is bypassed
    # when this process is started with SIGINT inherited as SIG_IGN (e.g. a
    # backgrounded job in a non-interactive shell, or under systemd/Docker).
    # Installing our own handler unconditionally re-enables clean shutdown
    # on both SIGINT and SIGTERM regardless of inherited disposition.
    try:
        name = signal.Signals(signum).name
    except ValueError:
        name = str(signum)
    print(f"\n[ctl] received {name} — initiating graceful shutdown", flush=True)
    _shutdown_event.set()


def main() -> int:
    if not NODE_BINARY.exists():
        print(
            f"[ctl] node binary not found at {NODE_BINARY}\n"
            f"      build first: g++ -std=c++17 -Wall -Wextra -pthread "
            f"src/node.cpp -o bin/node",
            file=sys.stderr,
        )
        return 1

    signal.signal(signal.SIGINT, _handle_signal)
    signal.signal(signal.SIGTERM, _handle_signal)

    LOG_DIR.mkdir(parents=True, exist_ok=True)
    topology = load_topology(TOPOLOGY_PATH)
    print(
        f"[ctl] loaded topology: {len(topology.nodes)} nodes, "
        f"{len(topology.edges)} edges",
        flush=True,
    )

    telemetry = TelemetryReceiver(TELEMETRY_PORT)
    telemetry.start()
    print(f"[ctl] telemetry receiver bound to udp/{TELEMETRY_PORT}", flush=True)

    nodes: list[SpawnedNode] = []
    try:
        for cfg in topology.nodes:
            sn = spawn_node(cfg, NODE_BINARY, TOPOLOGY_PATH, TELEMETRY_PORT, LOG_DIR)
            nodes.append(sn)
            print(
                f"[ctl] spawned id={cfg.id} role={cfg.role:<4} port={cfg.port} "
                f"pid={sn.process.pid}  log={LOG_DIR}/node-{cfg.id}.log",
                flush=True,
            )

        # Give children time to bind their ports and emit at least one
        # heartbeat before the first dashboard render. Interruptible by
        # signal because we wait on the shutdown event, not time.sleep.
        if _shutdown_event.wait(1.2):
            return 0

        while not _shutdown_event.is_set():
            render_dashboard(topology, nodes, telemetry)
            _shutdown_event.wait(DASHBOARD_REFRESH_SECONDS)
    finally:
        telemetry.stop()
        shutdown(nodes)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
