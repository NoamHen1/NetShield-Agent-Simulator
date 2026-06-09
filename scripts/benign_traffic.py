#!/usr/bin/env python3
"""
Benign background traffic generator for NetShield.

Simulates organic, low-volume application traffic between edge nodes so the
network metrics show steady activity. This proves the AI mitigation isolates
the attacker without disrupting legitimate flows. The C++ data plane only
routes packets; generating application traffic belongs in the control plane,
so this lives as a standalone Python script.

Usage:
    python3 scripts/benign_traffic.py
"""

import json
import random
import socket
import struct
import sys
import time
from pathlib import Path

# Wire format mirrors netshield::Packet from src/packet.h. See scripts/ddos.py.
PACKET_FORMAT = "!IHHBH512s"
PACKET_TYPE_DATA: int = 0
PAYLOAD_LEN: int = 32
PAYLOAD: bytes = b"BENIGN" * (PAYLOAD_LEN // 6) + b"\x00" * (PAYLOAD_LEN % 6)

TOPOLOGY_PATH = Path(__file__).parent.parent / "config" / "topology.json"

# Low-volume bounds — must stay well under the 10,000-packet anomaly threshold
# even if the same destination is repeatedly picked.
BURST_MIN: int = 1
BURST_MAX: int = 5
SLEEP_MIN: float = 0.05
SLEEP_MAX: float = 0.30
STATUS_INTERVAL: int = 500


def load_edge_nodes(topology_path: Path) -> list[tuple[int, int]]:
    """Return [(node_id, udp_port), ...] for every node with role == 'edge'."""
    with topology_path.open() as f:
        topology = json.load(f)

    edges = [
        (int(n["id"]), int(n["port"]))
        for n in topology["nodes"]
        if n.get("role") == "edge"
    ]

    if len(edges) < 2:
        print(
            f"[benign] Need at least 2 edge nodes to generate traffic, "
            f"found {len(edges)}.",
            file=sys.stderr,
        )
        sys.exit(1)

    return edges


def main() -> None:
    edge_nodes = load_edge_nodes(TOPOLOGY_PATH)
    edge_ids = [node_id for node_id, _ in edge_nodes]

    print(f"[benign] Edge nodes: {edge_ids}")
    print("[benign] Generating low-volume background traffic. Ctrl+C to stop.\n")

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    packet_id: int = 0
    total_sent: int = 0

    try:
        while True:
            src_id, src_port = random.choice(edge_nodes)
            dst_id, _ = random.choice([n for n in edge_nodes if n[0] != src_id])

            burst = random.randint(BURST_MIN, BURST_MAX)
            dest_addr = ("127.0.0.1", src_port)

            for _ in range(burst):
                datagram = struct.pack(
                    PACKET_FORMAT,
                    packet_id & 0xFFFF_FFFF,
                    src_id,
                    dst_id,
                    PACKET_TYPE_DATA,
                    PAYLOAD_LEN,
                    PAYLOAD.ljust(512, b"\x00"),
                )
                try:
                    sock.sendto(datagram, dest_addr)
                except OSError as exc:
                    print(f"[benign] sendto failed ({src_id}→{dst_id}): {exc}",
                          file=sys.stderr)
                    break

                packet_id += 1
                total_sent += 1

                if total_sent % STATUS_INTERVAL == 0:
                    print(f"[benign] Sent {total_sent} benign packets...")

            time.sleep(random.uniform(SLEEP_MIN, SLEEP_MAX))
    except KeyboardInterrupt:
        print(f"\n[benign] Stopped. Total benign packets sent: {total_sent:,}")
    finally:
        sock.close()


if __name__ == "__main__":
    main()
