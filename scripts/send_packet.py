#!/usr/bin/env python3
"""Send a NetShield Packet datagram to a node for manual testing.

Mirrors the wire format defined in src/packet.h:
    packet_id        u32
    source_node_id   u16
    dest_node_id     u16
    type             u8
    payload_len      u16
    payload          512 bytes
Total: 523 bytes, network byte order.
"""

from __future__ import annotations

import argparse
import socket
import struct
import sys

PACKET_FORMAT: str = "!IHHBH512s"
PACKET_SIZE: int = struct.calcsize(PACKET_FORMAT)
PAYLOAD_SIZE: int = 512


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=9000)
    p.add_argument("--id", dest="packet_id", type=int, default=42)
    p.add_argument("--src", type=int, default=1)
    p.add_argument("--dst", type=int, default=2)
    p.add_argument("--type", dest="ptype", type=int, default=0)
    p.add_argument("--payload", default="hello from python")
    p.add_argument(
        "--bad-len",
        action="store_true",
        help="Declare payload_len > 512 to trigger the node's bounds guard.",
    )
    p.add_argument(
        "--short",
        action="store_true",
        help="Truncate the datagram to trigger the node's size guard.",
    )
    p.add_argument(
        "--native-endian",
        action="store_true",
        help="Encode with little-endian to verify ntoh* decoding on the node.",
    )
    return p.parse_args()


def build_packet(args: argparse.Namespace) -> bytes:
    body = args.payload.encode()
    if len(body) > PAYLOAD_SIZE:
        sys.exit(f"payload too large: {len(body)} > {PAYLOAD_SIZE}")
    declared_len = 9999 if args.bad_len else len(body)
    # Swap to '<' (little-endian) only for the endianness diagnostic; the node
    # always decodes as network order, so this should produce a "wrong" id.
    fmt = "<IHHBH512s" if args.native_endian else PACKET_FORMAT
    return struct.pack(
        fmt,
        args.packet_id,
        args.src,
        args.dst,
        args.ptype,
        declared_len,
        body,
    )


def main() -> int:
    args = parse_args()
    pkt = build_packet(args)
    if args.short:
        pkt = pkt[:9]
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.sendto(pkt, (args.host, args.port))
    print(
        f"sent {len(pkt)} bytes to {args.host}:{args.port} "
        f"(id={args.packet_id} src={args.src} dst={args.dst} "
        f"type={args.ptype} payload_len={len(args.payload.encode())})"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
