#!/usr/bin/env python3
"""NetShield control plane: spawn, supervise, and visualize the C++ node fleet."""

from __future__ import annotations

import json
import os
import signal
import socket
import struct
import subprocess
import sys
import threading
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from types import FrameType
from typing import IO, Any

REPO_ROOT: Path = Path(__file__).resolve().parent.parent
NODE_BINARY: Path = REPO_ROOT / "bin" / "node"
TOPOLOGY_PATH: Path = REPO_ROOT / "config" / "topology.json"
LOG_DIR: Path = Path("/tmp/netshield")
LOGS_DIR: Path = REPO_ROOT / "logs"
ANOMALY_SNAPSHOT_PATH: Path = LOGS_DIR / "anomaly_snapshot.json"
SHUTDOWN_GRACE_SECONDS: float = 5.0
TELEMETRY_PORT: int = 9000
DASHBOARD_REFRESH_SECONDS: float = 2.0
HEARTBEAT_STALE_SECONDS: float = 3.0

# Per-node queue length that, when strictly exceeded, is treated as a DDoS
# signal worth snapshotting. Set well above steady-state burst depth so legit
# traffic spikes do not trip it.
QUEUE_ANOMALY_THRESHOLD: int = 10_000

# When a fresh anomaly is detected, the dashboard freezes the warning banner
# for this many seconds before resuming normal refresh, so the operator can
# read the alert before it scrolls past.
ANOMALY_PAUSE_SECONDS: float = 5.0

# Wire format — mirrors src/packet.h. Must stay in sync with the C++ side.
PACKET_FMT: str = "!IHHBH512s"
PACKET_SIZE: int = struct.calcsize(PACKET_FMT)
PACKET_TYPE_DATA: int = 0
PACKET_TYPE_CONTROL: int = 1
PACKET_TYPE_HEARTBEAT: int = 2

# Sentinel source_node_id for control-plane-originated CONTROL packets. Real
# nodes are 1..N; 0 is reserved as "control plane" so logs can distinguish.
CONTROL_PLANE_NODE_ID: int = 0

# Default Gemini model used by the AI worker. Kept here so the only place to
# bump versions is the control plane configuration block.
GEMINI_MODEL: str = "gemini-2.5-flash"

# ANSI escapes. Used for clear-screen and stale-cell highlighting in the
# dashboard. Auto-suppressed when stdout is not a TTY.
_USE_COLOR: bool = sys.stdout.isatty()
_CLEAR_SCREEN: str = "\033[H\033[2J" if _USE_COLOR else ""
_RED: str = "\033[31m" if _USE_COLOR else ""
_GREEN: str = "\033[32m" if _USE_COLOR else ""
_YELLOW: str = "\033[33m" if _USE_COLOR else ""
_DIM: str = "\033[2m" if _USE_COLOR else ""
_BOLD: str = "\033[1m" if _USE_COLOR else ""
_WHITE: str = "\033[97m" if _USE_COLOR else ""
_BG_RED: str = "\033[41m" if _USE_COLOR else ""
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


@dataclass(frozen=True)
class AnomalyAlert:
    node_id: int
    queue_size: int
    threshold: int
    detected_at_iso: str
    snapshot_path: Path


def _build_control_packet(seq: int, dest_node_id: int, block_id: int) -> bytes:
    """Pack a BLOCK:<id> CONTROL datagram in the C++ Packet wire format.

    source_node_id is the CONTROL_PLANE sentinel (0). dest_node_id is
    informational only — the actual recipient is determined by the UDP
    destination address; the field exists so node logs can record intent.
    """
    payload = f"BLOCK:{block_id}".encode("ascii")
    return struct.pack(
        PACKET_FMT,
        seq & 0xFFFF_FFFF,
        CONTROL_PLANE_NODE_ID,
        dest_node_id & 0xFFFF,
        PACKET_TYPE_CONTROL,
        len(payload),
        payload.ljust(512, b"\0"),
    )


class AnomalyDetector:
    """Watches heartbeats for queue overflow; snapshots state and drives AI mitigation.

    State machine: starts "armed". On the first heartbeat whose queue_size
    strictly exceeds the threshold, it (1) writes a topology+telemetry JSON
    snapshot, (2) spawns a background AI worker thread to call the Gemini
    pipeline and inject CONTROL packets, and (3) disarms. Re-arms only when
    every queue is back within tolerance AND the AI worker is no longer busy,
    so one attack produces exactly one analysis + one enforcement cycle.

    The dashboard thread reads AI state via ai_status_for_display(); the
    worker thread writes via _ai_lock. All shared state is guarded.
    """

    def __init__(
        self,
        threshold: int,
        snapshot_path: Path,
        topology: Topology,
    ) -> None:
        self._threshold = threshold
        self._snapshot_path = snapshot_path
        self._port_by_id: dict[int, int] = {
            n.id: n.port for n in topology.nodes
        }
        self._armed: bool = True
        self._last_alert: AnomalyAlert | None = None
        self._fresh: bool = False

        # AI worker state — guarded by _ai_lock so the dashboard thread can
        # read it without racing the worker.
        self._ai_lock = threading.Lock()
        self._ai_state: str = "idle"  # idle | analyzing | done | failed
        self._ai_started_at: float | None = None  # monotonic
        self._ai_finished_at: float | None = None
        self._ai_strategy: Any = None  # MitigationStrategy (lazy import)
        self._ai_error: str | None = None
        self._ai_enforced_cores: list[int] | None = None
        self._ai_thread: threading.Thread | None = None

    @property
    def last_alert(self) -> AnomalyAlert | None:
        return self._last_alert

    def consume_fresh(self) -> bool:
        """Returns True exactly once after each new detection, then resets."""
        was_fresh = self._fresh
        self._fresh = False
        return was_fresh

    def ai_status_for_display(self) -> dict[str, Any]:
        """Thread-safe read of the AI worker state for the dashboard."""
        with self._ai_lock:
            elapsed: float | None = None
            if self._ai_started_at is not None:
                end = self._ai_finished_at or time.monotonic()
                elapsed = end - self._ai_started_at
            return {
                "state": self._ai_state,
                "elapsed": elapsed,
                "strategy": self._ai_strategy,
                "error": self._ai_error,
                "enforced_cores": self._ai_enforced_cores,
            }

    def check(
        self,
        topology: Topology,
        heartbeats: dict[int, Heartbeat],
    ) -> None:
        if not heartbeats:
            return

        offenders = [
            hb for hb in heartbeats.values() if hb.queue_size > self._threshold
        ]
        with self._ai_lock:
            ai_busy = self._ai_state == "analyzing"

        if not offenders:
            # Only re-arm when AI is also idle — otherwise we'd risk firing a
            # new analysis before the current one finishes mitigating.
            if not ai_busy:
                self._armed = True
            return

        if not self._armed:
            return  # same attack, already captured

        worst = max(offenders, key=lambda hb: hb.queue_size)
        snapshot_dict, alert = self._snapshot(topology, heartbeats, worst)
        self._last_alert = alert
        self._armed = False
        self._fresh = True
        self._spawn_ai_worker(snapshot_dict)

    def _snapshot(
        self,
        topology: Topology,
        heartbeats: dict[int, Heartbeat],
        worst: Heartbeat,
    ) -> tuple[dict[str, Any], AnomalyAlert]:
        """Builds the snapshot dict in memory AND writes it to disk atomically."""
        now_wall = datetime.now(timezone.utc)
        now_mono = time.monotonic()
        snapshot: dict[str, Any] = {
            "detected_at": now_wall.isoformat(),
            "trigger": {
                "node_id": worst.node_id,
                "queue_size": worst.queue_size,
                "threshold": self._threshold,
            },
            "topology": {
                "nodes": [
                    {"id": n.id, "port": n.port, "role": n.role}
                    for n in topology.nodes
                ],
                "edges": [
                    {"from": e.src, "to": e.dst} for e in topology.edges
                ],
            },
            "telemetry": {
                str(hb.node_id): {
                    "queue_size": hb.queue_size,
                    "delivered": hb.delivered,
                    "forwarded": hb.forwarded,
                    "dropped": hb.dropped,
                    "age_seconds": round(now_mono - hb.received_at, 2),
                }
                for hb in heartbeats.values()
            },
        }

        # Atomic write: stage to .tmp, then rename. Guarantees a downstream
        # AI consumer never reads a half-written JSON document — POSIX rename
        # within the same filesystem is atomic.
        self._snapshot_path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self._snapshot_path.with_suffix(self._snapshot_path.suffix + ".tmp")
        with tmp.open("w", encoding="utf-8") as f:
            json.dump(snapshot, f, indent=2)
        tmp.replace(self._snapshot_path)

        alert = AnomalyAlert(
            node_id=worst.node_id,
            queue_size=worst.queue_size,
            threshold=self._threshold,
            detected_at_iso=now_wall.isoformat(),
            snapshot_path=self._snapshot_path,
        )
        return snapshot, alert

    # ------------------------------------------------------------------------
    # AI worker — background thread keeps the dashboard responsive while the
    # LLM round trip (seconds) and CONTROL-packet fan-out run asynchronously.
    # ------------------------------------------------------------------------
    def _spawn_ai_worker(self, snapshot_dict: dict[str, Any]) -> None:
        with self._ai_lock:
            self._ai_state = "analyzing"
            self._ai_started_at = time.monotonic()
            self._ai_finished_at = None
            self._ai_strategy = None
            self._ai_error = None
            self._ai_enforced_cores = None
        t = threading.Thread(
            target=self._ai_worker,
            args=(snapshot_dict,),
            daemon=True,
            name="ai-worker",
        )
        t.start()
        self._ai_thread = t

    def _ai_worker(self, snapshot_dict: dict[str, Any]) -> None:
        try:
            # Lazy import — keep google-genai a soft dependency. The control
            # plane stays runnable even when AI deps aren't installed; only
            # the worker fails with a clear "failed" state in that case.
            scripts_dir = REPO_ROOT / "scripts"
            if str(scripts_dir) not in sys.path:
                sys.path.insert(0, str(scripts_dir))
            from ai_orchestrator import (  # type: ignore[import-not-found]
                run_analyzer,
                run_strategist,
            )
            from google import genai  # type: ignore[import-not-found]

            api_key = os.environ.get("GEMINI_API_KEY")
            if not api_key:
                raise RuntimeError(
                    "GEMINI_API_KEY not set in control-plane environment"
                )

            client = genai.Client(api_key=api_key)
            analysis = run_analyzer(client, GEMINI_MODEL, snapshot_dict)
            strategy = run_strategist(
                client, GEMINI_MODEL, snapshot_dict, analysis
            )
            enforced = self._enforce_strategy(strategy)

            with self._ai_lock:
                self._ai_state = "done"
                self._ai_strategy = strategy
                self._ai_enforced_cores = enforced
                self._ai_finished_at = time.monotonic()
        except Exception as e:  # noqa: BLE001
            with self._ai_lock:
                self._ai_state = "failed"
                self._ai_error = f"{type(e).__name__}: {e}"
                self._ai_finished_at = time.monotonic()

    def _enforce_strategy(self, strategy: Any) -> list[int]:
        """Send a BLOCK CONTROL packet to each core node the AI chose.

        Returns the IDs actually contacted (unknown ones are skipped). UDP is
        fire-and-forget by design: if a CONTROL packet is lost, the next
        anomaly cycle will simply re-fire it — exactly the property that makes
        this enforcement pattern scale.
        """
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sent_to: list[int] = []
        try:
            for seq, core_id in enumerate(strategy.apply_to_core_nodes, start=1):
                port = self._port_by_id.get(core_id)
                if port is None:
                    continue
                pkt = _build_control_packet(
                    seq, core_id, strategy.block_source_id
                )
                try:
                    sock.sendto(pkt, ("127.0.0.1", port))
                    sent_to.append(core_id)
                except OSError:
                    pass  # node may have exited; idempotent re-fire on next cycle
        finally:
            sock.close()
        return sent_to


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


def _format_ai_line(ai_status: dict[str, Any]) -> str:
    state = ai_status["state"]
    elapsed = ai_status["elapsed"]
    elapsed_s = f" ({elapsed:.1f}s)" if elapsed is not None else ""

    if state == "idle":
        return " AI MITIGATION: idle"
    if state == "analyzing":
        return f" AI MITIGATION: AI Analyzing...{elapsed_s}"
    if state == "done":
        strategy = ai_status["strategy"]
        cores = ai_status["enforced_cores"] or []
        if strategy is not None:
            return (
                f" AI MITIGATION: {strategy.action} src={strategy.block_source_id}"
                f" -> CONTROL packets sent to cores {cores}{elapsed_s}"
            )
        return f" AI MITIGATION: done{elapsed_s}"
    if state == "failed":
        err = ai_status["error"] or "unknown error"
        return f" AI MITIGATION FAILED{elapsed_s}: {err}"
    return f" AI MITIGATION: {state}"


def _render_anomaly_banner(
    alert: AnomalyAlert,
    ai_status: dict[str, Any],
) -> None:
    label = f"{_BG_RED}{_BOLD}{_WHITE}"
    bar = "=" * 84
    line1 = (
        f" [!! ANOMALY !!] DDoS DETECTED -- node {alert.node_id} "
        f"queue={alert.queue_size:,} > threshold={alert.threshold:,}"
    )
    line2 = f" snapshot: {alert.snapshot_path}   at {alert.detected_at_iso}"
    line3 = _format_ai_line(ai_status)
    print(f"{label}{bar}{_RESET}")
    print(f"{label}{line1.ljust(84)[:84]}{_RESET}")
    print(f"{label}{line2.ljust(84)[:84]}{_RESET}")
    print(f"{label}{line3.ljust(84)[:84]}{_RESET}")
    print(f"{label}{bar}{_RESET}")


def render_dashboard(
    topology: Topology,
    nodes: list[SpawnedNode],
    telemetry: TelemetryReceiver,
    detector: AnomalyDetector,
) -> None:
    sys.stdout.write(_CLEAR_SCREEN)
    snap = telemetry.snapshot()
    detector.check(topology, snap)
    now = time.monotonic()

    print("NetShield Control Plane")
    print(
        f"  topology: {len(topology.nodes)} nodes, {len(topology.edges)} edges"
        f"   |   telemetry: udp/{telemetry.port}"
        f"   |   refresh: {DASHBOARD_REFRESH_SECONDS:.0f}s"
    )

    if detector.last_alert is not None:
        _render_anomaly_banner(detector.last_alert, detector.ai_status_for_display())

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
            over = hb.queue_size > QUEUE_ANOMALY_THRESHOLD
            queue_s = (
                f"{_RED}{_BOLD}{hb.queue_size}{_RESET}"
                if over
                else str(hb.queue_size)
            )
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

    detector = AnomalyDetector(
        QUEUE_ANOMALY_THRESHOLD, ANOMALY_SNAPSHOT_PATH, topology
    )
    print(
        f"[ctl] anomaly detector armed: queue > {QUEUE_ANOMALY_THRESHOLD:,} "
        f"-> snapshot to {ANOMALY_SNAPSHOT_PATH}",
        flush=True,
    )
    if os.environ.get("GEMINI_API_KEY"):
        print(
            f"[ctl] AI mitigation pipeline ready (model: {GEMINI_MODEL})",
            flush=True,
        )
    else:
        print(
            "[ctl] GEMINI_API_KEY not set -- AI mitigation will fail when "
            "an anomaly fires (snapshot will still be written).",
            flush=True,
        )

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
            render_dashboard(topology, nodes, telemetry, detector)
            # Default cadence; tightened while the AI worker is running so the
            # operator can watch the "Analyzing..." elapsed counter tick.
            ai_state = detector.ai_status_for_display()["state"]
            if detector.consume_fresh():
                pause = ANOMALY_PAUSE_SECONDS
            elif ai_state == "analyzing":
                pause = 1.0
            else:
                pause = DASHBOARD_REFRESH_SECONDS
            _shutdown_event.wait(pause)
    finally:
        telemetry.stop()
        shutdown(nodes)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
