#!/usr/bin/env python3
"""Step 3 integration test for the NetShield mesh.

Spawns the control plane, fires a battery of probe packets across the
8-node topology, and parses each per-node log in /tmp/netshield/ for the
expected FORWARD / DELIVER / DROP markers — one expectation pinned to a
specific node's log, so we prove a packet actually traversed the
predicted hops rather than just appearing in some line of stdout.

The headline case is the edge-to-edge path 1 -> 4 -> 8: ingress at edge
node 1, transit through core node 4, delivery at edge node 8. Passing
also implicitly proves the mutex protecting NodeState isn't stalling the
recv loop — if it were, packets would pile up beyond the per-test settle
window and tests would fail with "missing" log entries.

Exit status: 0 = all pass, 1 = some failed, 2 = harness error.
"""

from __future__ import annotations

import signal
import socket
import struct
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path

REPO_ROOT: Path = Path(__file__).resolve().parent.parent
CTL_CMD: list[str] = ["python3", str(REPO_ROOT / "control_plane" / "main.py")]
LOG_DIR: Path = Path("/tmp/netshield")
CTL_LOG: Path = Path("/tmp/netshield-test-ctl.log")
NODE_IDS: tuple[int, ...] = tuple(range(1, 9))
PACKET_FMT: str = "!IHHBH512s"
HOST: str = "127.0.0.1"
SETTLE_SECONDS: float = 0.5
MESH_READY_TIMEOUT: float = 10.0

GREEN, RED, YELLOW, DIM, RESET = (
    "\033[32m", "\033[31m", "\033[33m", "\033[2m", "\033[0m"
)
USE_COLOR: bool = sys.stdout.isatty()


def c(text: str, code: str) -> str:
    return f"{code}{text}{RESET}" if USE_COLOR else text


@dataclass(frozen=True)
class Expectation:
    """A substring that must appear in a specific node's log."""
    node_id: int
    needle: str


@dataclass(frozen=True)
class Test:
    name: str
    ingress_port: int
    dst: int
    packet_id: int
    expect: tuple[Expectation, ...]
    src: int = 99


# Pinning each expectation to a node_id is the whole point of the file-based
# design: a FORWARD line for node 4 must appear in node-4.log, not just
# somewhere in interleaved stdout. This catches forwarding logic that
# accidentally short-circuits the actual hop.
TESTS: tuple[Test, ...] = (
    Test(
        "direct delivery at edge node 1",
        ingress_port=8001, dst=1, packet_id=1001,
        expect=(
            Expectation(1, "DELIVER id=1001 src=99 dst=1"),
        ),
    ),
    Test(
        "1-hop forward edge -> core: 1 -> 3",
        ingress_port=8001, dst=3, packet_id=1002,
        expect=(
            Expectation(1, "FORWARD id=1002 src=99 dst=3 via next_hop=3"),
            Expectation(3, "DELIVER id=1002 src=99 dst=3"),
        ),
    ),
    Test(
        "2-hop forward across mesh: 1 -> 3 -> 7",
        ingress_port=8001, dst=7, packet_id=1003,
        expect=(
            Expectation(1, "FORWARD id=1003 src=99 dst=7 via next_hop=3"),
            Expectation(3, "FORWARD id=1003 src=99 dst=7 via next_hop=7"),
            Expectation(7, "DELIVER id=1003 src=99 dst=7"),
        ),
    ),
    Test(
        "2-hop forward across mesh: 8 -> 6 -> 2",
        ingress_port=8008, dst=2, packet_id=1004,
        expect=(
            Expectation(8, "FORWARD id=1004 src=99 dst=2 via next_hop=6"),
            Expectation(6, "FORWARD id=1004 src=99 dst=2 via next_hop=2"),
            Expectation(2, "DELIVER id=1004 src=99 dst=2"),
        ),
    ),
    Test(
        "edge -> edge via core (headline Step 3 case): 1 -> 4 -> 8",
        ingress_port=8001, dst=8, packet_id=1005,
        expect=(
            Expectation(1, "FORWARD id=1005 src=99 dst=8 via next_hop=4"),
            Expectation(4, "FORWARD id=1005 src=99 dst=8 via next_hop=8"),
            Expectation(8, "DELIVER id=1005 src=99 dst=8"),
        ),
    ),
    Test(
        "path asymmetry — same dst, different ingress: 2 -> 6 -> 8",
        ingress_port=8002, dst=8, packet_id=1006,
        expect=(
            Expectation(2, "FORWARD id=1006 src=99 dst=8 via next_hop=6"),
            Expectation(6, "FORWARD id=1006 src=99 dst=8 via next_hop=8"),
            Expectation(8, "DELIVER id=1006 src=99 dst=8"),
        ),
    ),
    Test(
        "unreachable destination dropped at ingress",
        ingress_port=8001, dst=99, packet_id=1007,
        expect=(
            Expectation(1, "DROP id=1007 src=99 dst=99: no route"),
        ),
    ),
    Test(
        "core-to-core direct: 3 -> 6",
        ingress_port=8003, dst=6, packet_id=1008,
        expect=(
            Expectation(3, "FORWARD id=1008 src=99 dst=6 via next_hop=6"),
            Expectation(6, "DELIVER id=1008 src=99 dst=6"),
        ),
    ),
)


def build_packet(
    packet_id: int, src: int, dst: int, payload: str = "test"
) -> bytes:
    body = payload.encode()
    return struct.pack(PACKET_FMT, packet_id, src, dst, 0, len(body), body)


def send_packet(port: int, packet_id: int, src: int, dst: int) -> None:
    pkt = build_packet(packet_id, src, dst)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.sendto(pkt, (HOST, port))


def read_node_log(node_id: int) -> str:
    path = LOG_DIR / f"node-{node_id}.log"
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


def wait_for_mesh_ready(timeout: float) -> bool:
    deadline = time.monotonic() + timeout
    needle = "listening on UDP port"
    while time.monotonic() < deadline:
        if all(needle in read_node_log(nid) for nid in NODE_IDS):
            return True
        time.sleep(0.1)
    return False


def run_test(test: Test) -> bool:
    send_packet(test.ingress_port, test.packet_id, test.src, test.dst)

    deadline = time.monotonic() + SETTLE_SECONDS
    missing: list[Expectation] = list(test.expect)
    while missing and time.monotonic() < deadline:
        still_missing: list[Expectation] = []
        for exp in missing:
            if exp.needle not in read_node_log(exp.node_id):
                still_missing.append(exp)
        missing = still_missing
        if missing:
            time.sleep(0.02)

    if not missing:
        print(f"  {c('PASS', GREEN)}  {test.name}")
        return True

    print(f"  {c('FAIL', RED)}  {test.name}")
    for exp in missing:
        print(
            f"    {c(f'missing in node-{exp.node_id}.log:', YELLOW)} "
            f"{exp.needle}"
        )
        log_tail = "\n".join(read_node_log(exp.node_id).splitlines()[-10:])
        if log_tail:
            print(c(f"    last 10 lines of node-{exp.node_id}.log:", DIM))
            for line in log_tail.splitlines():
                print(c(f"      {line}", DIM))
    return False


def _purge_node_logs() -> None:
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    for nid in NODE_IDS:
        try:
            (LOG_DIR / f"node-{nid}.log").unlink()
        except FileNotFoundError:
            pass


def main() -> int:
    # Wipe stale logs so a previous run's packet IDs can't satisfy this run's
    # expectations. The control plane truncates these files on spawn anyway,
    # but deleting first means we never observe the previous content while
    # waiting for the mesh to come up.
    _purge_node_logs()

    ctl_log_file = CTL_LOG.open("w", encoding="utf-8")
    print(c(f"[harness] starting control plane (log: {CTL_LOG})", DIM))
    proc = subprocess.Popen(
        CTL_CMD,
        stdout=ctl_log_file,
        stderr=subprocess.STDOUT,
    )

    passed = 0
    failed = 0
    try:
        if not wait_for_mesh_ready(MESH_READY_TIMEOUT):
            print(c(f"[harness] mesh did not become ready within "
                    f"{MESH_READY_TIMEOUT}s", RED))
            print(c(f"[harness] control plane stdout ({CTL_LOG}):", DIM))
            ctl_log_file.flush()
            try:
                for line in CTL_LOG.read_text().splitlines()[-30:]:
                    print(c(f"  {line}", DIM))
            except OSError:
                pass
            return 2

        # A tiny extra moment for each recv loop to be armed past startup.
        time.sleep(0.2)
        print(f"[harness] mesh up, running {len(TESTS)} tests\n")

        for test in TESTS:
            if run_test(test):
                passed += 1
            else:
                failed += 1
    finally:
        print(c("\n[harness] shutting down control plane (SIGINT)...", DIM))
        if proc.poll() is None:
            proc.send_signal(signal.SIGINT)
            try:
                proc.wait(timeout=10.0)
            except subprocess.TimeoutExpired:
                print(c("[harness] SIGINT timed out; sending SIGKILL", RED))
                proc.kill()
                proc.wait()
        ctl_log_file.close()

    total = passed + failed
    summary = (
        f"[harness] {c(str(passed) + ' passed', GREEN)}, "
        f"{c(str(failed) + ' failed', RED if failed else DIM)} "
        f"({total} total)"
    )
    print(f"\n{summary}")
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
