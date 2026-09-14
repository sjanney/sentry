// SPDX-License-Identifier: Apache-2.0
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

static void attempt_ipv4(int type)
{
    struct sockaddr_in address = {
        .sin_family = AF_INET,
        .sin_port = htons(9),
    };
    int socket_fd = socket(AF_INET, type, 0);

    inet_pton(AF_INET, "127.0.0.1", &address.sin_addr);
    if (socket_fd >= 0) {
        (void)connect(socket_fd, (const struct sockaddr *)&address,
                      sizeof(address));
        close(socket_fd);
    }
}

static void attempt_ipv6(int type)
{
    struct sockaddr_in6 address = {
        .sin6_family = AF_INET6,
        .sin6_port = htons(9),
    };
    int socket_fd = socket(AF_INET6, type, 0);

    inet_pton(AF_INET6, "::1", &address.sin6_addr);
    if (socket_fd >= 0) {
        (void)connect(socket_fd, (const struct sockaddr *)&address,
                      sizeof(address));
        close(socket_fd);
    }
}

int main(void)
{
    attempt_ipv4(SOCK_STREAM);
    attempt_ipv4(SOCK_DGRAM);
    attempt_ipv6(SOCK_STREAM);
    attempt_ipv6(SOCK_DGRAM);
    return 0;
}
