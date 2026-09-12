// SPDX-License-Identifier: Apache-2.0
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <sys/stat.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

int main(int argc, char **argv)
{
    const char *object_path;
    const char *protected_path = "/tmp/sentry-lsm-protected";
    const char *workspace_path = "/tmp/sentry-lsm-workspace";
    const char *hardlink_path = "/tmp/sentry-lsm-protected-hardlink";
    const char *symlink_path = "/tmp/sentry-lsm-protected-symlink";
    struct bpf_object *object = NULL;
    struct bpf_program *program;
    struct bpf_map *map;
    struct bpf_link *lsm_link = NULL;
    uint64_t protected_inode;
    uint8_t enabled = 1;
    struct stat protected_stat;
    int protected_fd = -1;
    int inherited_fd = -1;
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
    inherited_fd = open(protected_path, O_RDONLY);
    if (inherited_fd < 0) {
        perror("open inherited descriptor before policy activation");
        goto out;
    }
    protected_fd = open(workspace_path, O_CREAT | O_WRONLY | O_TRUNC, 0600);
    if (protected_fd < 0 || close(protected_fd) != 0 ||
        link(protected_path, hardlink_path) != 0 || symlink(protected_path, symlink_path) != 0 ||
        stat(protected_path, &protected_stat) != 0) {
        perror("prepare filesystem policy fixtures");
        goto out;
    }
    protected_fd = -1;
    protected_inode = (uint64_t)protected_stat.st_ino;

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
    map = bpf_object__find_map_by_name(object, "blocked_inodes");
    if (!program || !map) {
        fprintf(stderr, "required BPF program or map is missing\n");
        goto out;
    }
    lsm_link = bpf_program__attach_lsm(program);
    if (!lsm_link) {
        fprintf(stderr, "attach BPF LSM program failed\n");
        goto out;
    }
    if (bpf_map_update_elem(bpf_map__fd(map), &protected_inode, &enabled, BPF_ANY) != 0) {
        perror("enable synthetic deny rule");
        goto out;
    }

    /* file_open cannot revoke an already-open descriptor. This is intentional
     * evidence for the policy rejection described in the limitations doc. */
    if (read(inherited_fd, &(char){0}, 0) != 0) {
        perror("expected inherited descriptor to remain usable");
        goto out;
    }

    protected_fd = open(workspace_path, O_RDONLY);
    if (protected_fd < 0 || close(protected_fd) != 0) {
        perror("expected workspace open to succeed");
        goto out;
    }
    protected_fd = -1;

    errno = 0;
    protected_fd = open(protected_path, O_RDONLY);
    if (protected_fd != -1 || errno != EACCES) {
        fprintf(stderr, "expected protected open to fail with EACCES, got fd=%d errno=%d\n",
                protected_fd, errno);
        goto out;
    }
    errno = 0;
    protected_fd = open(hardlink_path, O_RDONLY);
    if (protected_fd != -1 || errno != EACCES) {
        fprintf(stderr, "expected hardlink open to fail with EACCES, got fd=%d errno=%d\n",
                protected_fd, errno);
        goto out;
    }
    errno = 0;
    protected_fd = open(symlink_path, O_RDONLY);
    if (protected_fd != -1 || errno != EACCES) {
        fprintf(stderr, "expected symlink open to fail with EACCES, got fd=%d errno=%d\n",
                protected_fd, errno);
        goto out;
    }
    puts("BPF LSM selective file-open denial, alias checks, and inherited-FD limitation succeeded");
    result = 0;

out:
    if (protected_fd >= 0)
        close(protected_fd);
    if (inherited_fd >= 0)
        close(inherited_fd);
    if (lsm_link)
        bpf_link__destroy(lsm_link);
    if (object)
        bpf_object__close(object);
    unlink(protected_path);
    unlink(workspace_path);
    unlink(hardlink_path);
    unlink(symlink_path);
    return result;
}
