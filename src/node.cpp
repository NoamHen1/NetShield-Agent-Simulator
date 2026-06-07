#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <algorithm>
#include <cerrno>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <mutex>
#include <queue>
#include <stdexcept>
#include <thread>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

#include "packet.h"
#include "routing.h"
#include "topology.h"

using netshield::Packet;
using netshield::PacketType;

static constexpr int  BASE10              = 10;
static constexpr auto HEARTBEAT_INTERVAL  = std::chrono::seconds(1);

// Application consumer cadence. The sleep simulates real per-packet
// processing time, keeping the queue depth a meaningful load signal rather
// than letting it drain instantly. The batch caps how many packets a single
// critical section pops, so the producer (recv loop) isn't starved if the
// queue is deep.
static constexpr auto APPLICATION_DRAIN_INTERVAL = std::chrono::milliseconds(5);
static constexpr std::size_t APPLICATION_DRAIN_BATCH = 1000;

namespace {

sockaddr_in make_loopback_addr(int port) {
    sockaddr_in a{};
    a.sin_family      = AF_INET;
    a.sin_port        = htons(static_cast<uint16_t>(port));
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    return a;
}

// Shared mutable state accessed by both the recv loop (main thread) and the
// heartbeat thread. Every access goes through `mtx` via lock_guard — no
// exceptions. We deliberately keep all shared state in one struct so the
// synchronization story is "this aggregate is guarded by this mutex" rather
// than scattered through file-scope globals.
struct NodeState {
    std::mutex mtx;
    std::queue<Packet> packet_queue;  // local-delivery queue
    std::uint64_t delivered = 0;      // packets terminated at this node
    std::uint64_t forwarded = 0;      // packets handed off to a next hop
    std::uint64_t dropped   = 0;      // packets discarded (no route, malformed, etc.)

    // Dynamic ACL: source_node_ids whose DATA traffic we silently drop. Mutated
    // only by CONTROL packets from the Python control plane; read O(1) on the
    // hot path. Guarded by `mtx` like everything else in NodeState.
    std::unordered_set<int> blocked_sources;
};

// Application consumer thread — drains state.packet_queue at a bounded rate.
//
// Closes the producer/consumer loop: without it the recv loop pushes to a
// queue nothing ever pops, so queue_size grows monotonically and any
// downstream state machine that re-arms on "queue subsided" (e.g. the Python
// AnomalyDetector) gets stuck forever after a single attack.
//
// Design notes:
//   * One mutex acquisition per drain cycle, batched up to APPLICATION_DRAIN_BATCH
//     pops. Acquiring per-packet would dominate the cost; batching amortizes it.
//   * The critical section does only O(N) pops on a std::queue (no I/O, no
//     allocations beyond what pop frees), so the producer is never blocked
//     for long even at peak depth.
//   * The sleep models real application work between batches. Without it the
//     consumer would drain instantly and queue_size would never meaningfully
//     reflect sustained load.
void application_loop(NodeState& state) {
    while (true) {
        // 1. Sleep OUTSIDE the lock so we don't freeze the router.
        // 10ms sleep × 50 packets/batch = 5,000 pkts/sec drain rate,
        // fast enough to clear a post-attack target-node backlog promptly.
        std::this_thread::sleep_for(std::chrono::milliseconds(10));

        // 2. Lock and pop a STRICT maximum of 50 packets
        std::lock_guard<std::mutex> lock(state.mtx);
        int popped = 0;
        while (!state.packet_queue.empty() && popped < 50) {
            state.packet_queue.pop();
            popped++;
        }
    }
}

void telemetry_loop(int node_id, int telemetry_port, NodeState& state) {
    const int sockfd = ::socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        std::fprintf(stderr, "[node %d] telemetry socket() failed: %s\n",
                     node_id, std::strerror(errno));
        return;
    }
    const sockaddr_in ctl_addr = make_loopback_addr(telemetry_port);
    std::uint32_t hb_seq = 0;

    while (true) {
        std::this_thread::sleep_for(HEARTBEAT_INTERVAL);

        // Snapshot the metrics under the lock, then release BEFORE doing any
        // I/O. Holding the mutex across sendto() would let a stalled kernel
        // send buffer block the recv loop's tiny critical sections.
        std::uint64_t q_size, d, f, dr;
        {
            std::lock_guard<std::mutex> lock(state.mtx);
            q_size = state.packet_queue.size();
            d      = state.delivered;
            f      = state.forwarded;
            dr     = state.dropped;
        }

        ++hb_seq;
        Packet pkt{};
        pkt.packet_id      = htonl(hb_seq);
        pkt.source_node_id = htons(static_cast<std::uint16_t>(node_id));
        pkt.dest_node_id   = htons(0);  // 0 = control plane sink; not L3-routed
        pkt.type           = static_cast<std::uint8_t>(PacketType::HEARTBEAT);

        char body[netshield::PAYLOAD_SIZE];
        const int written = std::snprintf(
            body, sizeof(body),
            "queue=%llu delivered=%llu forwarded=%llu dropped=%llu",
            static_cast<unsigned long long>(q_size),
            static_cast<unsigned long long>(d),
            static_cast<unsigned long long>(f),
            static_cast<unsigned long long>(dr)
        );
        const std::uint16_t plen = (written < 0)
            ? 0
            : static_cast<std::uint16_t>(
                std::min(static_cast<std::size_t>(written),
                         netshield::PAYLOAD_SIZE));
        pkt.payload_len = htons(plen);
        std::memcpy(pkt.payload, body, plen);

        if (::sendto(sockfd, &pkt, sizeof(pkt), 0,
                     reinterpret_cast<const sockaddr*>(&ctl_addr),
                     sizeof(ctl_addr)) < 0) {
            std::fprintf(stderr, "[node %d] telemetry sendto failed: %s\n",
                         node_id, std::strerror(errno));
        }
    }
}

}  // namespace

int main(int argc, char* argv[]) {
    if (argc != 4) {
        std::fprintf(stderr,
                     "Usage: %s <node_id> <topology_path> <telemetry_port>\n",
                     argv[0]);
        return EXIT_FAILURE;
    }

    const int node_id = static_cast<int>(std::strtol(argv[1], nullptr, BASE10));
    if (node_id <= 0) {
        std::fprintf(stderr, "Error: node_id must be positive\n");
        return EXIT_FAILURE;
    }

    const int telemetry_port =
        static_cast<int>(std::strtol(argv[3], nullptr, BASE10));
    if (telemetry_port <= 0 || telemetry_port > 65535) {
        std::fprintf(stderr, "Error: telemetry_port must be in 1-65535\n");
        return EXIT_FAILURE;
    }

    // --- topology + endpoint table ------------------------------------------
    netshield::topology::Topology topo;
    try {
        topo = netshield::topology::parse(argv[2]);
    } catch (const std::exception& ex) {
        std::fprintf(stderr, "[node %d] topology parse failed: %s\n",
                     node_id, ex.what());
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
    for (const auto& n : topo.nodes) adj[n.id];
    for (const auto& e : topo.edges) {
        adj[e.from].push_back(e.to);
        adj[e.to].push_back(e.from);
    }

    // --- Dijkstra: build next-hop routing table -----------------------------
    const std::unordered_map<int, int> routing_table =
        netshield::routing::build_routing_table(node_id, adj);

    std::vector<std::pair<int, int>> sorted_rt(routing_table.begin(),
                                                routing_table.end());
    std::sort(sorted_rt.begin(), sorted_rt.end());
    std::printf("[node %d] routing table (%zu destinations):\n",
                node_id, sorted_rt.size());
    for (const auto& [dest, next_hop] : sorted_rt) {
        std::printf("[node %d]   dest=%d  next_hop=%d\n", node_id, dest, next_hop);
    }

    // --- socket + bind ------------------------------------------------------
    const int sockfd = ::socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        std::fprintf(stderr, "[node %d] socket() failed: %s\n",
                     node_id, std::strerror(errno));
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

    std::printf("[node %d] listening on UDP port %d (%zu-byte frames), "
                "telemetry -> %d\n",
                node_id, my_port, sizeof(Packet), telemetry_port);
    std::fflush(stdout);

    NodeState state;

    // Spawn the heartbeat + application-consumer threads. detach() because
    // we never join — the process is signal-killed by the control plane on
    // shutdown, taking every thread with it. The consumer is what keeps
    // queue_size a meaningful load signal: without it, heartbeats would
    // report monotonically growing queue depth forever.
    std::thread(telemetry_loop, node_id, telemetry_port, std::ref(state)).detach();
    std::thread(application_loop, std::ref(state)).detach();

    alignas(Packet) char buf[sizeof(Packet)];

    while (true) {
        sockaddr_in sender_addr{};
        socklen_t   sender_len = sizeof(sender_addr);

        const ssize_t bytes = ::recvfrom(
            sockfd, buf, sizeof(buf), 0,
            reinterpret_cast<sockaddr*>(&sender_addr), &sender_len
        );

        if (bytes < 0) {
            std::fprintf(stderr, "[node %d] recvfrom failed: %s\n",
                         node_id, std::strerror(errno));
            continue;
        }
        if (static_cast<std::size_t>(bytes) != sizeof(Packet)) {
            std::fprintf(stderr,
                         "[node %d] dropped malformed datagram (%zd bytes, expected %zu)\n",
                         node_id, bytes, sizeof(Packet));
            std::lock_guard<std::mutex> lock(state.mtx);
            ++state.dropped;
            continue;
        }

        const Packet* wire = reinterpret_cast<const Packet*>(buf);
        const std::uint32_t pid  = ntohl(wire->packet_id);
        const std::uint16_t src  = ntohs(wire->source_node_id);
        const std::uint16_t dest = ntohs(wire->dest_node_id);

        // -- CONTROL plane: parse policy update before any data-path work. ----
        // CONTROL packets carry plain-ASCII policy commands from the Python
        // control plane, e.g. "BLOCK:1" → add source node 1 to the ACL. Kept
        // simple-by-design: the channel is loopback-only and the data plane
        // never originates CONTROL itself.
        if (wire->type == static_cast<std::uint8_t>(PacketType::CONTROL)) {
            const std::uint16_t plen = ntohs(wire->payload_len);
            if (plen == 0 || plen > netshield::PAYLOAD_SIZE) {
                std::fprintf(stderr,
                             "[node %d] CONTROL id=%u: bad payload_len=%u\n",
                             node_id, pid, plen);
                continue;
            }
            // Null-terminated copy so sscanf is safe — payload on the wire is
            // not guaranteed to be terminated.
            char body[netshield::PAYLOAD_SIZE + 1] = {0};
            std::memcpy(body, wire->payload, plen);

            int block_id = -1;
            if (std::sscanf(body, "BLOCK:%d", &block_id) == 1 && block_id > 0) {
                std::uint64_t purged = 0;
                {
                    std::lock_guard<std::mutex> lock(state.mtx);
                    state.blocked_sources.insert(block_id);

                    // Active Queue Purging: std::queue has no erase(), so we
                    // rebuild it by popping every element into a clean temp
                    // queue, discarding any packet whose source matches the
                    // newly-blocked ID. This is O(N) but happens once per
                    // CONTROL packet — latency here beats letting megabytes of
                    // attack traffic linger in memory until the consumer drains.
                    std::queue<Packet> clean;
                    while (!state.packet_queue.empty()) {
                        Packet p = state.packet_queue.front();
                        state.packet_queue.pop();
                        if (static_cast<int>(p.source_node_id) == block_id) {
                            ++purged;
                            ++state.dropped;
                        } else {
                            clean.push(std::move(p));
                        }
                    }
                    state.packet_queue = std::move(clean);
                }
                std::printf(
                    "[node %d] ENFORCING FIREWALL: node %d blocked, "
                    "purged %llu queued packets\n",
                    node_id, block_id,
                    static_cast<unsigned long long>(purged));
                std::fflush(stdout);
            } else {
                std::fprintf(stderr,
                             "[node %d] CONTROL id=%u: unrecognized payload \"%s\"\n",
                             node_id, pid, body);
            }
            continue;
        }

        // -- ACL gate on the DATA path. ----------------------------------------
        // O(1) hashset lookup under a brief lock. Performed BEFORE both
        // delivery and forwarding so a blocked source cannot transit this node
        // by either path. Silent drop — by design, attackers learn nothing.
        {
            std::lock_guard<std::mutex> lock(state.mtx);
            if (state.blocked_sources.count(static_cast<int>(src)) != 0) {
                ++state.dropped;
                continue;
            }
        }

        if (static_cast<int>(dest) == node_id) {
            Packet pkt{};
            pkt.packet_id      = pid;
            pkt.source_node_id = src;
            pkt.dest_node_id   = dest;
            pkt.type           = wire->type;
            pkt.payload_len    = ntohs(wire->payload_len);
            if (pkt.payload_len > netshield::PAYLOAD_SIZE) {
                std::fprintf(stderr, "[node %d] dropped id=%u: payload_len=%u > %zu\n",
                             node_id, pid, pkt.payload_len, netshield::PAYLOAD_SIZE);
                std::lock_guard<std::mutex> lock(state.mtx);
                ++state.dropped;
                continue;
            }
            std::memcpy(pkt.payload, wire->payload, pkt.payload_len);

            std::printf("[node %d] DELIVER id=%u src=%u dst=%u payload_len=%u\n",
                        node_id, pid, src, dest, pkt.payload_len);
            std::fflush(stdout);

            std::lock_guard<std::mutex> lock(state.mtx);
            state.packet_queue.push(pkt);
            ++state.delivered;
            continue;
        }

        const auto rt_it = routing_table.find(static_cast<int>(dest));
        if (rt_it == routing_table.end()) {
            std::fprintf(stderr, "[node %d] DROP id=%u src=%u dst=%u: no route\n",
                         node_id, pid, src, dest);
            std::lock_guard<std::mutex> lock(state.mtx);
            ++state.dropped;
            continue;
        }
        const int next_hop = rt_it->second;
        const auto ep_it = endpoints.find(next_hop);
        if (ep_it == endpoints.end()) {
            std::fprintf(stderr, "[node %d] DROP id=%u dst=%u: no endpoint for next_hop=%d\n",
                         node_id, pid, dest, next_hop);
            std::lock_guard<std::mutex> lock(state.mtx);
            ++state.dropped;
            continue;
        }
        const sockaddr_in& nh_addr = ep_it->second;
        const ssize_t sent = ::sendto(
            sockfd, buf, sizeof(Packet), 0,
            reinterpret_cast<const sockaddr*>(&nh_addr), sizeof(nh_addr)
        );
        if (sent < 0) {
            std::fprintf(stderr, "[node %d] sendto next_hop=%d failed: %s\n",
                         node_id, next_hop, std::strerror(errno));
            std::lock_guard<std::mutex> lock(state.mtx);
            ++state.dropped;
            continue;
        }
        std::printf("[node %d] FORWARD id=%u src=%u dst=%u via next_hop=%d\n",
                    node_id, pid, src, dest, next_hop);
        std::fflush(stdout);

        std::lock_guard<std::mutex> lock(state.mtx);
        ++state.forwarded;
    }

    ::close(sockfd);
    return EXIT_SUCCESS;
}
