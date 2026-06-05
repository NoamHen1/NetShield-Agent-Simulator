#ifndef NETSHIELD_ROUTING_H
#define NETSHIELD_ROUTING_H

#include <climits>
#include <functional>
#include <queue>
#include <unordered_map>
#include <utility>
#include <vector>

namespace netshield::routing {

// Build a next-hop routing table from `source` to every reachable destination
// using Dijkstra over `adj` (node_id -> list of neighbor ids). Edge weight is
// 1, so this is effectively BFS; the heap is retained so non-unit weights
// (latency, bandwidth cost) can be added later without re-architecting.
//
// Returned map: dest_id -> next_hop_id. Excludes the source itself and
// unreachable destinations (they are simply absent from the map; callers
// should treat lookup-miss as "no route").
//
// Complexity: O((V + E) log V). For V=8 / E=14 (~28 directed entries) this is
// ~100 ops per node — negligible at startup, runs once.
inline std::unordered_map<int, int> build_routing_table(
    int source,
    const std::unordered_map<int, std::vector<int>>& adj
) {
    constexpr int INF = INT_MAX;
    std::unordered_map<int, int> dist;
    std::unordered_map<int, int> prev;

    for (const auto& kv : adj) {
        dist[kv.first] = INF;
        prev[kv.first] = -1;
    }
    dist[source] = 0;

    using Entry = std::pair<int, int>;  // (distance, node_id)
    std::priority_queue<Entry, std::vector<Entry>, std::greater<Entry>> pq;
    pq.push({0, source});

    while (!pq.empty()) {
        const auto [d, u] = pq.top();
        pq.pop();
        // Lazy stale-entry discard: cheaper than implementing decrease-key.
        if (d > dist[u]) continue;

        const auto adj_it = adj.find(u);
        if (adj_it == adj.end()) continue;
        for (const int v : adj_it->second) {
            const auto dit = dist.find(v);
            if (dit == dist.end()) continue;
            const int nd = d + 1;
            if (nd < dit->second) {
                dit->second = nd;
                prev[v] = u;
                pq.push({nd, v});
            }
        }
    }

    // Derive next hop from the predecessor chain: walk back from `dest`
    // until the predecessor is `source`; that walk-stopping node is the hop
    // we hand the packet to first.
    std::unordered_map<int, int> routing_table;
    for (const auto& kv : dist) {
        const int dest = kv.first;
        if (dest == source || kv.second == INF) continue;
        int cur = dest;
        while (prev[cur] != source && prev[cur] != -1) {
            cur = prev[cur];
        }
        if (prev[cur] == source) {
            routing_table[dest] = cur;
        }
    }
    return routing_table;
}

}  // namespace netshield::routing

#endif  // NETSHIELD_ROUTING_H
