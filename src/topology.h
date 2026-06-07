#ifndef NETSHIELD_TOPOLOGY_H
#define NETSHIELD_TOPOLOGY_H

#include <cctype>
#include <cstddef>
#include <cstdlib>
#include <fstream>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

namespace netshield::topology {

struct NodeInfo {
    int id;
    int port;
};

struct EdgeInfo {
    int from;
    int to;
};

struct Topology {
    std::vector<NodeInfo> nodes;
    std::vector<EdgeInfo> edges;
};

namespace detail {

// Purpose-built integer-field extractor for our known topology.json schema.
// NOT a general-purpose JSON parser — assumes the key is unique within `obj`
// and is followed by a colon and an integer literal. Throws on malformed input.
inline int extract_int(const std::string& obj, const std::string& key) {
    const std::string needle = "\"" + key + "\"";
    const std::size_t kpos = obj.find(needle);
    if (kpos == std::string::npos) {
        throw std::runtime_error("topology: missing key \"" + key + "\"");
    }
    const std::size_t cpos = obj.find(':', kpos + needle.size());
    if (cpos == std::string::npos) {
        throw std::runtime_error("topology: missing ':' after key \"" + key + "\"");
    }
    std::size_t p = cpos + 1;
    while (p < obj.size() && std::isspace(static_cast<unsigned char>(obj[p]))) {
        ++p;
    }
    char* end = nullptr;
    const long v = std::strtol(obj.c_str() + p, &end, 10);
    if (end == obj.c_str() + p) {
        throw std::runtime_error("topology: invalid integer for key \"" + key + "\"");
    }
    return static_cast<int>(v);
}

// Iterate "{...}" objects between the array brackets following the given key,
// invoking `consume` on each object's substring.
template <typename Consume>
inline void for_each_object_in_array(const std::string& s,
                                     const std::string& array_key,
                                     Consume consume) {
    const std::string needle = "\"" + array_key + "\"";
    const std::size_t kpos = s.find(needle);
    if (kpos == std::string::npos) {
        throw std::runtime_error("topology: missing array \"" + array_key + "\"");
    }
    const std::size_t lbrack = s.find('[', kpos);
    const std::size_t rbrack = s.find(']', lbrack);
    if (lbrack == std::string::npos || rbrack == std::string::npos) {
        throw std::runtime_error("topology: malformed array \"" + array_key + "\"");
    }
    std::size_t p = lbrack;
    while (true) {
        const std::size_t obj_start = s.find('{', p);
        if (obj_start == std::string::npos || obj_start > rbrack) break;
        const std::size_t obj_end = s.find('}', obj_start);
        if (obj_end == std::string::npos || obj_end > rbrack) {
            throw std::runtime_error("topology: unterminated object in \"" + array_key + "\"");
        }
        consume(s.substr(obj_start, obj_end - obj_start + 1));
        p = obj_end + 1;
    }
}

}  // namespace detail

inline Topology parse(const std::string& path) {
    std::ifstream f(path);
    if (!f) {
        throw std::runtime_error("topology: cannot open " + path);
    }
    std::stringstream buf;
    buf << f.rdbuf();
    const std::string s = buf.str();

    Topology t;
    detail::for_each_object_in_array(s, "nodes", [&](const std::string& obj) {
        t.nodes.push_back({detail::extract_int(obj, "id"),
                           detail::extract_int(obj, "port")});
    });
    detail::for_each_object_in_array(s, "edges", [&](const std::string& obj) {
        t.edges.push_back({detail::extract_int(obj, "from"),
                           detail::extract_int(obj, "to")});
    });
    return t;
}

}  // namespace netshield::topology

#endif  // NETSHIELD_TOPOLOGY_H
