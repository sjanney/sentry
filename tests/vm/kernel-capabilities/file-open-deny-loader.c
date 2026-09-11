// SPDX-License-Identifier: Apache-2.0
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

int main(int argc, char **argv)
{
    const char *object_path;
    const char *protected_path = "/tmp/sentry-lsm-protected";
    struct bpf_object *object = NULL;
    struct bpf_program *program;
    struct bpf_map *map;
    struct bpf_link *link = NULL;
    uint32_t tgid = (uint32_t)getpid();
    uint8_t enabled = 1;
    int protected_fd = -1;
    int result = 1;

    if (argc != 2) {
        fprintf(stderr, "usage: %s BPF_OBJECT\n", argv[0]);
        return 2;
    }
    object_path = argv[1];

    protected_fd = open(protected_path, O_CREAT | O_WRONLY | O_TRUNC, 0600);
    if (protected_fd < 0) {
        perror("create synthetic protected file");
        goto out;
    }
    if (close(protected_fd) != 0) {
        perror("close synthetic protected file");
        protected_fd = -1;
        goto out;
    }
    protected_fd = -1;

    object = bpf_object__open_file(object_path, NULL);
    if (!object) {
        fprintf(stderr, "open BPF object failed\n");
        goto out;
    }
    if (bpf_object__load(object) != 0) {
        fprintf(stderr, "load BPF LSM object failed\n");
        goto out;
    }
    program = bpf_object__find_program_by_name(object, "deny_file_open");
    map = bpf_object__find_map_by_name(object, "blocked_tgids");
    if (!program || !map) {
        fprintf(stderr, "required BPF program or map is missing\n");
        goto out;
    }
    link = bpf_program__attach_lsm(program);
    if (!link) {
        fprintf(stderr, "attach BPF LSM program failed\n");
        goto out;
    }
    if (bpf_map_update_elem(bpf_map__fd(map), &tgid, &enabled, BPF_ANY) != 0) {
        perror("enable synthetic deny rule");
        goto out;
    }

    errno = 0;
    protected_fd = open(protected_path, O_RDONLY);
    if (protected_fd != -1 || errno != EACCES) {
        fprintf(stderr, "expected protected open to fail with EACCES, got fd=%d errno=%d\n",
                protected_fd, errno);
        goto out;
    }
    puts("BPF LSM file-open denial succeeded");
    result = 0;

out:
    if (protected_fd >= 0)
        close(protected_fd);
    if (link)
        bpf_link__destroy(link);
    if (object)
        bpf_object__close(object);
    unlink(protected_path);
    return result;
}
