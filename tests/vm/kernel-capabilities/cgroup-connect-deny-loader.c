// SPDX-License-Identifier: Apache-2.0
#include <arpa/inet.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/socket.h>
#include <unistd.h>

static int expect_ipv4_deny(int socket_type)
{
    const struct sockaddr_in address = {
        .sin_family = AF_INET,
        .sin_addr.s_addr = htonl(INADDR_LOOPBACK),
        .sin_port = htons(9),
    };
    int fd = socket(AF_INET, socket_type, 0);
    if (fd < 0 || connect(fd, (const struct sockaddr *)&address, sizeof(address)) != -1 || errno != EPERM) {
        fprintf(stderr, "expected IPv4 type %d to fail with EPERM, errno=%d\n", socket_type, errno);
        if (fd >= 0)
            close(fd);
        return -1;
    }
    close(fd);
    return 0;
}

static int expect_existing_ipv4_socket_deny(int fd)
{
    const struct sockaddr_in address = {
        .sin_family = AF_INET,
        .sin_addr.s_addr = htonl(INADDR_LOOPBACK),
        .sin_port = htons(9),
    };
    if (connect(fd, (const struct sockaddr *)&address, sizeof(address)) != -1 || errno != EPERM) {
        fprintf(stderr, "expected pre-activation IPv4 socket to fail with EPERM, errno=%d\n", errno);
        return -1;
    }
    return 0;
}

static int expect_ipv6_deny(int socket_type)
{
    const struct sockaddr_in6 address = {
        .sin6_family = AF_INET6,
        .sin6_addr = IN6ADDR_LOOPBACK_INIT,
        .sin6_port = htons(9),
    };
    int fd = socket(AF_INET6, socket_type, 0);
    if (fd < 0 || connect(fd, (const struct sockaddr *)&address, sizeof(address)) != -1 || errno != EPERM) {
        fprintf(stderr, "expected IPv6 type %d to fail with EPERM, errno=%d\n", socket_type, errno);
        if (fd >= 0)
            close(fd);
        return -1;
    }
    close(fd);
    return 0;
}

int main(int argc, char **argv)
{
    struct bpf_object *object = NULL;
    struct bpf_program *program4;
    struct bpf_program *program6;
    struct bpf_map *map;
    struct bpf_link *link4 = NULL;
    struct bpf_link *link6 = NULL;
    uint32_t tgid = (uint32_t)getpid();
    uint8_t enabled = 1;
    int cgroup_fd = -1;
    int pre_activation_socket = -1;
    int result = 1;

    if (argc != 2) {
        fprintf(stderr, "usage: %s BPF_OBJECT\n", argv[0]);
        return 2;
    }
    pre_activation_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (pre_activation_socket < 0) {
        perror("create pre-activation socket");
        goto out;
    }
    cgroup_fd = open("/sys/fs/cgroup", O_RDONLY | O_DIRECTORY);
    if (cgroup_fd < 0) {
        perror("open target cgroup");
        goto out;
    }
    object = bpf_object__open_file(argv[1], NULL);
    if (!object || bpf_object__load(object) != 0) {
        fprintf(stderr, "load cgroup BPF object failed\n");
        goto out;
    }
    program4 = bpf_object__find_program_by_name(object, "deny_connect4");
    program6 = bpf_object__find_program_by_name(object, "deny_connect6");
    map = bpf_object__find_map_by_name(object, "blocked_tgids");
    if (!program4 || !program6 || !map) {
        fprintf(stderr, "required BPF programs or map are missing\n");
        goto out;
    }
    link4 = bpf_program__attach_cgroup(program4, cgroup_fd);
    link6 = bpf_program__attach_cgroup(program6, cgroup_fd);
    if (!link4 || !link6) {
        fprintf(stderr, "attach cgroup BPF programs failed\n");
        goto out;
    }
    if (bpf_map_update_elem(bpf_map__fd(map), &tgid, &enabled, BPF_ANY) != 0) {
        perror("enable synthetic connect deny rule");
        goto out;
    }
    if (expect_ipv4_deny(SOCK_STREAM) != 0 || expect_ipv4_deny(SOCK_DGRAM) != 0 ||
        expect_ipv6_deny(SOCK_STREAM) != 0 || expect_ipv6_deny(SOCK_DGRAM) != 0)
        goto out;
    if (expect_existing_ipv4_socket_deny(pre_activation_socket) != 0)
        goto out;
    puts("cgroup IPv4/IPv6 TCP/UDP and pre-activation socket egress denials succeeded");
    result = 0;

out:
    if (link6)
        bpf_link__destroy(link6);
    if (link4)
        bpf_link__destroy(link4);
    if (object)
        bpf_object__close(object);
    if (cgroup_fd >= 0)
        close(cgroup_fd);
    if (pre_activation_socket >= 0)
        close(pre_activation_socket);
    return result;
}
