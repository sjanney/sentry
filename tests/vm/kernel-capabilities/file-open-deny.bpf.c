// SPDX-License-Identifier: Apache-2.0
#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define SENTRY_EACCES 13

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4);
    __type(key, __u64);
    __type(value, __u8);
} blocked_inodes SEC(".maps");

SEC("lsm/file_open")
int BPF_PROG(deny_file_open, struct file *file, int ret)
{
    __u64 inode;

    if (ret)
        return ret;
    inode = BPF_CORE_READ(file, f_inode, i_ino);
    if (bpf_map_lookup_elem(&blocked_inodes, &inode))
        return -SENTRY_EACCES;
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
