// SPDX-License-Identifier: Apache-2.0
#include <arpa/inet.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

int main(int argc, char **argv)
{
    struct sockaddr_in listener_address = {
        .sin_family = AF_INET,
        .sin_addr.s_addr = htonl(INADDR_LOOPBACK),
        .sin_port = 0,
    };
    struct bpf_object *object = NULL;
    struct bpf_program *program;
    struct bpf_map *map;
    struct bpf_link *link = NULL;
    socklen_t address_length = sizeof(listener_address);
    uint32_t tgid = (uint32_t)getpid();
    uint8_t enabled = 1;
    int cgroup_fd = -1;
    int listener_fd = -1;
    int client_fd = -1;
    int result = 1;

    if (argc != 2) {
        fprintf(stderr, "usage: %s BPF_OBJECT\n", argv[0]);
        return 2;
    }
    listener_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (listener_fd < 0 ||
        bind(listener_fd, (struct sockaddr *)&listener_address, sizeof(listener_address)) != 0 ||
        listen(listener_fd, 1) != 0 ||
        getsockname(listener_fd, (struct sockaddr *)&listener_address, &address_length) != 0) {
        perror("create synthetic local listener");
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
    program = bpf_object__find_program_by_name(object, "deny_connect4");
    map = bpf_object__find_map_by_name(object, "blocked_tgids");
    if (!program || !map) {
        fprintf(stderr, "required BPF program or map is missing\n");
        goto out;
    }
    link = bpf_program__attach_cgroup(program, cgroup_fd);
    if (!link) {
        fprintf(stderr, "attach cgroup BPF program failed\n");
        goto out;
    }
    if (bpf_map_update_elem(bpf_map__fd(map), &tgid, &enabled, BPF_ANY) != 0) {
        perror("enable synthetic connect deny rule");
        goto out;
    }
    client_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (client_fd < 0) {
        perror("create synthetic client");
        goto out;
    }
    errno = 0;
    if (connect(client_fd, (struct sockaddr *)&listener_address, sizeof(listener_address)) != -1 ||
        errno != EPERM) {
        fprintf(stderr, "expected local connect to fail with EPERM, got errno=%d\n", errno);
        goto out;
    }
    puts("cgroup egress denial succeeded");
    result = 0;

out:
    if (client_fd >= 0)
        close(client_fd);
    if (link)
        bpf_link__destroy(link);
    if (object)
        bpf_object__close(object);
    if (cgroup_fd >= 0)
        close(cgroup_fd);
    if (listener_fd >= 0)
        close(listener_fd);
    return result;
}
