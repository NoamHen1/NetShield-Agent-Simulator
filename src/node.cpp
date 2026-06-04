#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>

static constexpr int    MAX_PAYLOAD = 1024;
static constexpr int    BASE10      = 10;

int main(int argc, char* argv[]) {
    if (argc != 2) {
        std::fprintf(stderr, "Usage: %s <port>\n", argv[0]);
        return EXIT_FAILURE;
    }

    const int port = static_cast<int>(std::strtol(argv[1], nullptr, BASE10));
    if (port <= 0 || port > 65535) {
        std::fprintf(stderr, "Error: port must be in range 1–65535\n");
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

    std::printf("[node] Listening on UDP port %d\n", port);
    std::fflush(stdout);

    // Stack-allocated receive buffer — preferred for low-latency packet processing.
    char buf[MAX_PAYLOAD];

    // --- recvfrom() loop ----------------------------------------------------
    // Blocks the thread in the kernel wait queue until a datagram arrives.
    // Captures sender address so future steps can reply or update routing tables.
    while (true) {
        sockaddr_in sender_addr{};
        socklen_t   sender_len = sizeof(sender_addr);

        const ssize_t bytes = ::recvfrom(
            sockfd,
            buf,
            sizeof(buf) - 1,
            0,
            reinterpret_cast<sockaddr*>(&sender_addr),
            &sender_len
        );

        if (bytes < 0) {
            std::fprintf(stderr, "recvfrom() failed: %s\n", std::strerror(errno));
            continue;
        }

        buf[bytes] = '\0';  // null-terminate for safe printf

        char sender_ip[INET_ADDRSTRLEN];
        ::inet_ntop(AF_INET, &sender_addr.sin_addr, sender_ip, sizeof(sender_ip));

        std::printf("[node] %s:%d -> \"%s\" (%zd bytes)\n",
                    sender_ip,
                    ntohs(sender_addr.sin_port),
                    buf,
                    bytes);
        std::fflush(stdout);
    }

    ::close(sockfd);
    return EXIT_SUCCESS;
}
