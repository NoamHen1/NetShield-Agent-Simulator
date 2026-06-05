#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <queue>

#include "packet.h"

using netshield::Packet;

static constexpr int BASE10 = 10;

int main(int argc, char* argv[]) {
    if (argc != 2) {
        std::fprintf(stderr, "Usage: %s <port>\n", argv[0]);
        return EXIT_FAILURE;
    }

    const int port = static_cast<int>(std::strtol(argv[1], nullptr, BASE10));
    if (port <= 0 || port > 65535) {
        std::fprintf(stderr, "Error: port must be in range 1-65535\n");
        return EXIT_FAILURE;
    }

    // --- socket() -----------------------------------------------------------
    // Asks the kernel to allocate a UDP socket (SOCK_DGRAM over AF_INET).
    // Returns a file descriptor indexing this process's fd table.
    const int sockfd = ::socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        std::fprintf(stderr, "socket() failed: %s\n", std::strerror(errno));
        return EXIT_FAILURE;
    }

    // Allow rapid restart on the same port (avoids TIME_WAIT bind failures).
    const int reuse = 1;
    if (::setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse)) < 0) {
        std::fprintf(stderr, "setsockopt(SO_REUSEADDR) failed: %s\n", std::strerror(errno));
        ::close(sockfd);
        return EXIT_FAILURE;
    }

    // --- bind() -------------------------------------------------------------
    // Registers this socket in the kernel's UDP demultiplexer table under the
    // given port. INADDR_ANY accepts packets on all local network interfaces.
    sockaddr_in local_addr{};
    local_addr.sin_family      = AF_INET;
    local_addr.sin_port        = htons(static_cast<uint16_t>(port));
    local_addr.sin_addr.s_addr = INADDR_ANY;

    if (::bind(sockfd, reinterpret_cast<const sockaddr*>(&local_addr), sizeof(local_addr)) < 0) {
        std::fprintf(stderr, "bind() on port %d failed: %s\n", port, std::strerror(errno));
        ::close(sockfd);
        return EXIT_FAILURE;
    }

    std::printf("[node] Listening on UDP port %d (expecting %zu-byte Packet frames)\n",
                port, sizeof(Packet));
    std::fflush(stdout);

    // Stack-allocated receive buffer sized exactly to the wire format.
    // Reading into a char[] lets us safely reinterpret_cast to Packet*: the
    // C++ aliasing rules explicitly permit inspecting any object through a
    // char/unsigned char pointer.
    alignas(Packet) char buf[sizeof(Packet)];

    // In-memory packet queue. Single-threaded for this milestone; a lock-free
    // SPSC variant lands when the worker thread is introduced.
    std::queue<Packet> packet_queue;

    // --- recvfrom() loop ----------------------------------------------------
    // Blocks the thread in the kernel wait queue until a datagram arrives.
    // Captures sender address so future steps can reply or update routing tables.
    while (true) {
        sockaddr_in sender_addr{};
        socklen_t   sender_len = sizeof(sender_addr);

        const ssize_t bytes = ::recvfrom(
            sockfd,
            buf,
            sizeof(buf),
            0,
            reinterpret_cast<sockaddr*>(&sender_addr),
            &sender_len
        );

        if (bytes < 0) {
            std::fprintf(stderr, "recvfrom() failed: %s\n", std::strerror(errno));
            continue;
        }

        // Length validation BEFORE casting. A short read would let us read
        // uninitialized stack bytes; an oversized datagram means the sender
        // is speaking a different protocol version. Drop either case.
        if (static_cast<std::size_t>(bytes) != sizeof(Packet)) {
            char sender_ip[INET_ADDRSTRLEN];
            ::inet_ntop(AF_INET, &sender_addr.sin_addr, sender_ip, sizeof(sender_ip));
            std::fprintf(stderr,
                         "[node] dropped malformed datagram from %s:%d (%zd bytes, expected %zu)\n",
                         sender_ip,
                         ntohs(sender_addr.sin_port),
                         bytes,
                         sizeof(Packet));
            continue;
        }

        // Safe reinterpret: buf is char[] with Packet alignment and matching size.
        const Packet* wire = reinterpret_cast<const Packet*>(buf);

        // Decode wire (network byte order) into a host-order copy. We copy by
        // value into the queue so the next recvfrom() can overwrite buf.
        Packet pkt{};
        pkt.packet_id      = ntohl(wire->packet_id);
        pkt.source_node_id = ntohs(wire->source_node_id);
        pkt.dest_node_id   = ntohs(wire->dest_node_id);
        pkt.type           = wire->type;  // single byte: no conversion needed
        pkt.payload_len    = ntohs(wire->payload_len);

        // Guard against a sender claiming a payload_len larger than the buffer.
        if (pkt.payload_len > netshield::PAYLOAD_SIZE) {
            std::fprintf(stderr,
                         "[node] dropped packet id=%u: payload_len=%u exceeds capacity=%zu\n",
                         pkt.packet_id,
                         pkt.payload_len,
                         netshield::PAYLOAD_SIZE);
            continue;
        }
        std::memcpy(pkt.payload, wire->payload, pkt.payload_len);

        char sender_ip[INET_ADDRSTRLEN];
        ::inet_ntop(AF_INET, &sender_addr.sin_addr, sender_ip, sizeof(sender_ip));

        std::printf("[node] rx from %s:%d  id=%u  src=%u  dst=%u  type=%u  payload_len=%u\n",
                    sender_ip,
                    ntohs(sender_addr.sin_port),
                    pkt.packet_id,
                    pkt.source_node_id,
                    pkt.dest_node_id,
                    static_cast<unsigned>(pkt.type),
                    pkt.payload_len);
        std::fflush(stdout);

        packet_queue.push(pkt);
    }

    ::close(sockfd);
    return EXIT_SUCCESS;
}
