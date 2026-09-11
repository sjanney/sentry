// SPDX-License-Identifier: Apache-2.0
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define SENTRY_EACCES 13

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u8);
} blocked_tgids SEC(".maps");

SEC("lsm/file_open")
int BPF_PROG(deny_file_open, struct file *file, int ret)
{
    __u32 tgid = bpf_get_current_pid_tgid() >> 32;

    if (ret)
        return ret;
    if (bpf_map_lookup_elem(&blocked_tgids, &tgid))
        return -SENTRY_EACCES;
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
