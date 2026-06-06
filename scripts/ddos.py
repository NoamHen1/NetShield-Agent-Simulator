#!/usr/bin/env python3
"""
DDoS flood simulator for NetShield integration testing.

Reads the network topology to locate the attacker node's UDP port, then
injects a continuous stream of binary-packed Packet datagrams into that
node. The attacker node routes them toward the target, generating realistic
flood traffic through the mesh.

Usage:
    python3 scripts/ddos.py --attacker 1 --target 8
"""

import argparse
import json
import socket
import struct
import sys
from pathlib import Path

# Wire format mirrors netshield::Packet from src/packet.h.
# '!' = network byte order (big-endian), no padding — matches __attribute__((packed)).
# I  = uint32_t  packet_id
# H  = uint16_t  source_node_id
# H  = uint16_t  dest_node_id
# B  = uint8_t   type  (0 = DATA)
# H  = uint16_t  payload_len
# 512s = uint8_t payload[512]
PACKET_FORMAT = "!IHHBH512s"
PACKET_TYPE_DATA: int = 0
PAYLOAD_LEN: int = 64
PAYLOAD: bytes = b"FLOOD" * (PAYLOAD_LEN // 5) + b"\x00" * (PAYLOAD_LEN % 5)
STATUS_INTERVAL: int = 10_000

TOPOLOGY_PATH = Path(__file__).parent.parent / "config" / "topology.json"


def load_attacker_port(topology_path: Path, attacker_id: int) -> int:
    with topology_path.open() as f:
        topology = json.load(f)

    for node in topology["nodes"]:
        if node["id"] == attacker_id:
            return int(node["port"])

    known_ids = [n["id"] for n in topology["nodes"]]
    print(
        f"[error] Node {attacker_id} not found in topology. "
        f"Known IDs: {known_ids}",
        file=sys.stderr,
    )
    sys.exit(1)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Inject a UDP flood into a NetShield attacker node."
    )
    parser.add_argument(
        "--attacker",
        type=int,
        required=True,
        metavar="NODE_ID",
        help="Node ID that originates the flood (its port receives injected packets).",
    )
    parser.add_argument(
        "--target",
        type=int,
        required=True,
        metavar="NODE_ID",
        help="Destination node ID embedded in each packet header.",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    attacker_port = load_attacker_port(TOPOLOGY_PATH, args.attacker)

    print(
        f"[ddos] Flooding node {args.attacker} (port {attacker_port}) "
        f"→ target node {args.target}"
    )
    print("[ddos] Press Ctrl+C to stop.\n")

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    dest = ("127.0.0.1", attacker_port)
    packet_id: int = 0

    try:
        while True:
            datagram = struct.pack(
                PACKET_FORMAT,
                packet_id & 0xFFFF_FFFF,
                args.attacker,
                args.target,
                PACKET_TYPE_DATA,
                PAYLOAD_LEN,
                PAYLOAD.ljust(512, b"\x00"),
            )
            sock.sendto(datagram, dest)
            packet_id += 1

            if packet_id % STATUS_INTERVAL == 0:
                print(f"[ddos] Flooded {packet_id // 1000}k packets...")
    except KeyboardInterrupt:
        print(f"\n[ddos] Stopped. Total packets sent: {packet_id:,}")
    finally:
        sock.close()


if __name__ == "__main__":
    main()
