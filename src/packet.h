#ifndef NETSHIELD_PACKET_H
#define NETSHIELD_PACKET_H

#include <cstddef>
#include <cstdint>

namespace netshield {

// Wire-format constants. PAYLOAD_SIZE is chosen to keep the full datagram
// well under the typical Ethernet MTU (1500 B) after IP+UDP headers (28 B),
// avoiding IP-layer fragmentation in the common case.
inline constexpr std::size_t PAYLOAD_SIZE = 512;

// Packet type discriminator. Kept as a uint8_t for compact wire encoding.
enum class PacketType : std::uint8_t {
    DATA      = 0,
    CONTROL   = 1,
    HEARTBEAT = 2,
    ROUTE_ADV = 3,
};

// Packed wire-format packet.
//
// __attribute__((packed)) suppresses all compiler padding so the in-memory
// layout matches the byte-for-byte layout on the network. Without this, the
// compiler is free to insert padding for alignment, which would silently
// corrupt the format across builds/architectures.
//
// All multi-byte integer fields travel in NETWORK byte order (big-endian)
// on the wire. Convert with htons/htonl on send and ntohs/ntohl on receive.
struct __attribute__((packed)) Packet {
    std::uint32_t packet_id;                 // monotonic id assigned by source
    std::uint16_t source_node_id;            // logical node id of sender
    std::uint16_t dest_node_id;              // logical node id of intended receiver
    std::uint8_t  type;                      // PacketType value
    std::uint16_t payload_len;               // valid bytes in `payload` (<= PAYLOAD_SIZE)
    std::uint8_t  payload[PAYLOAD_SIZE];     // fixed-size payload buffer
};

// Compile-time guarantee that the struct has no hidden padding. If a future
// edit accidentally introduces a hole, the build breaks instead of silently
// shipping a broken wire format.
static_assert(
    sizeof(Packet) == sizeof(std::uint32_t)   // packet_id
                    + sizeof(std::uint16_t)   // source_node_id
                    + sizeof(std::uint16_t)   // dest_node_id
                    + sizeof(std::uint8_t)    // type
                    + sizeof(std::uint16_t)   // payload_len
                    + PAYLOAD_SIZE,           // payload
    "netshield::Packet has unexpected padding — wire format would be corrupt"
);

}  // namespace netshield

#endif  // NETSHIELD_PACKET_H
