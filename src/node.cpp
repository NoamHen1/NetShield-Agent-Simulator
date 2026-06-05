#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <algorithm>
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <queue>
#include <stdexcept>
#include <unordered_map>
#include <utility>
#include <vector>

#include "packet.h"
#include "routing.h"
#include "topology.h"

using netshield::Packet;

static constexpr int BASE10 = 10;

namespace {

sockaddr_in make_loopback_addr(int port) {
    sockaddr_in a{};
    a.sin_family      = AF_INET;
    a.sin_port        = htons(static_cast<uint16_t>(port));
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    return a;
}

}  // namespace

int main(int argc, char* argv[]) {
    if (argc != 3) {
        std::fprintf(stderr, "Usage: %s <node_id> <topology_path>\n", argv[0]);
        return EXIT_FAILURE;
    }

    const int node_id = static_cast<int>(std::strtol(argv[1], nullptr, BASE10));
    if (node_id <= 0) {
        std::fprintf(stderr, "Error: node_id must be positive\n");
        return EXIT_FAILURE;
    }

    // --- topology + endpoint table ------------------------------------------
    netshield::topology::Topology topo;
    try {
        topo = netshield::topology::parse(argv[2]);
    } catch (const std::exception& ex) {
        std::fprintf(stderr, "[node %d] topology parse failed: %s\n", node_id, ex.what());
        return EXIT_FAILURE;
    }

    int my_port = -1;
    std::unordered_map<int, sockaddr_in> endpoints;
    endpoints.reserve(topo.nodes.size());
    for (const auto& n : topo.nodes) {
        endpoints.emplace(n.id, make_loopback_addr(n.port));
        if (n.id == node_id) my_port = n.port;
    }
    if (my_port < 0) {
        std::fprintf(stderr, "[node %d] not found in topology\n", node_id);
        return EXIT_FAILURE;
    }

    // --- adjacency list (undirected) ----------------------------------------
    std::unordered_map<int, std::vector<int>> adj;
    adj.reserve(topo.nodes.size());
    for (const auto& n : topo.nodes) adj[n.id];  // ensure isolated nodes appear
    for (const auto& e : topo.edges) {
        adj[e.from].push_back(e.to);
        adj[e.to].push_back(e.from);
    }

    // --- Dijkstra: build this node's next-hop routing table -----------------
    const std::unordered_map<int, int> routing_table =
        netshield::routing::build_routing_table(node_id, adj);

    // Stable, sorted print for readability across runs.
    std::vector<std::pair<int, int>> sorted_rt(routing_table.begin(), routing_table.end());
    std::sort(sorted_rt.begin(), sorted_rt.end());
    std::printf("[node %d] routing table (%zu destinations):\n",
                node_id, sorted_rt.size());
    for (const auto& [dest, next_hop] : sorted_rt) {
        std::printf("[node %d]   dest=%d  next_hop=%d\n", node_id, dest, next_hop);
    }

    // --- socket + bind ------------------------------------------------------
    const int sockfd = ::socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        std::fprintf(stderr, "[node %d] socket() failed: %s\n", node_id, std::strerror(errno));
        return EXIT_FAILURE;
    }

    const int reuse = 1;
    if (::setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse)) < 0) {
        std::fprintf(stderr, "[node %d] setsockopt(SO_REUSEADDR) failed: %s\n",
                     node_id, std::strerror(errno));
        ::close(sockfd);
        return EXIT_FAILURE;
    }

    sockaddr_in local_addr{};
    local_addr.sin_family      = AF_INET;
    local_addr.sin_port        = htons(static_cast<uint16_t>(my_port));
    local_addr.sin_addr.s_addr = INADDR_ANY;
    if (::bind(sockfd, reinterpret_cast<const sockaddr*>(&local_addr), sizeof(local_addr)) < 0) {
        std::fprintf(stderr, "[node %d] bind() on port %d failed: %s\n",
                     node_id, my_port, std::strerror(errno));
        ::close(sockfd);
        return EXIT_FAILURE;
    }

    std::printf("[node %d] listening on UDP port %d (%zu-byte frames)\n",
                node_id, my_port, sizeof(Packet));
    std::fflush(stdout);

    // Stack receive buffer sized to wire format. Kept around as the source for
    // zero-copy forwarding: we never re-encode, we sendto() the original bytes.
    alignas(Packet) char buf[sizeof(Packet)];

    // Local-delivery queue. Forwarded packets do NOT enter this queue — they
    // are transit traffic and should leave on the wire without dwell time.
    std::queue<Packet> packet_queue;

    // --- recvfrom + forward/deliver loop ------------------------------------
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
            std::fprintf(stderr, "[node %d] recvfrom failed: %s\n",
                         node_id, std::strerror(errno));
            continue;
        }
        if (static_cast<std::size_t>(bytes) != sizeof(Packet)) {
            std::fprintf(stderr, "[node %d] dropped malformed datagram (%zd bytes, expected %zu)\n",
                         node_id, bytes, sizeof(Packet));
            continue;
        }

        // Inspect the header in-place. Forwarding does NOT rewrite the buffer.
        const Packet* wire = reinterpret_cast<const Packet*>(buf);
        const std::uint32_t pid  = ntohl(wire->packet_id);
        const std::uint16_t src  = ntohs(wire->source_node_id);
        const std::uint16_t dest = ntohs(wire->dest_node_id);

        if (static_cast<int>(dest) == node_id) {
            // Local delivery — fully decode and enqueue.
            Packet pkt{};
            pkt.packet_id      = pid;
            pkt.source_node_id = src;
            pkt.dest_node_id   = dest;
            pkt.type           = wire->type;
            pkt.payload_len    = ntohs(wire->payload_len);
            if (pkt.payload_len > netshield::PAYLOAD_SIZE) {
                std::fprintf(stderr, "[node %d] dropped id=%u: payload_len=%u > %zu\n",
                             node_id, pid, pkt.payload_len, netshield::PAYLOAD_SIZE);
                continue;
            }
            std::memcpy(pkt.payload, wire->payload, pkt.payload_len);

            std::printf("[node %d] DELIVER id=%u src=%u dst=%u payload_len=%u\n",
                        node_id, pid, src, dest, pkt.payload_len);
            std::fflush(stdout);
            packet_queue.push(pkt);
            continue;
        }

        // Forwarding path: one routing-table lookup + one endpoint lookup +
        // one sendto(). No copy of the payload, no re-serialization.
        const auto rt_it = routing_table.find(static_cast<int>(dest));
        if (rt_it == routing_table.end()) {
            std::fprintf(stderr, "[node %d] DROP id=%u src=%u dst=%u: no route\n",
                         node_id, pid, src, dest);
            continue;
        }
        const int next_hop = rt_it->second;
        const auto ep_it = endpoints.find(next_hop);
        if (ep_it == endpoints.end()) {
            std::fprintf(stderr, "[node %d] DROP id=%u dst=%u: no endpoint for next_hop=%d\n",
                         node_id, pid, dest, next_hop);
            continue;
        }
        const sockaddr_in& nh_addr = ep_it->second;
        const ssize_t sent = ::sendto(
            sockfd,
            buf,
            sizeof(Packet),
            0,
            reinterpret_cast<const sockaddr*>(&nh_addr),
            sizeof(nh_addr)
        );
        if (sent < 0) {
            std::fprintf(stderr, "[node %d] sendto next_hop=%d failed: %s\n",
                         node_id, next_hop, std::strerror(errno));
            continue;
        }
        std::printf("[node %d] FORWARD id=%u src=%u dst=%u via next_hop=%d\n",
                    node_id, pid, src, dest, next_hop);
        std::fflush(stdout);
    }

    ::close(sockfd);
    return EXIT_SUCCESS;
}
