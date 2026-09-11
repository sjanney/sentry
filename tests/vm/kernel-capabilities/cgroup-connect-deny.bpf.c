// SPDX-License-Identifier: Apache-2.0
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u8);
} blocked_tgids SEC(".maps");

static __always_inline int deny_connect(struct bpf_sock_addr *ctx)
{
    __u32 tgid = bpf_get_current_pid_tgid() >> 32;

    if (bpf_map_lookup_elem(&blocked_tgids, &tgid))
        return 0;
    return 1;
}

SEC("cgroup/connect4")
int deny_connect4(struct bpf_sock_addr *ctx)
{
    return deny_connect(ctx);
}

SEC("cgroup/connect6")
int deny_connect6(struct bpf_sock_addr *ctx)
{
    return deny_connect(ctx);
}

char LICENSE[] SEC("license") = "GPL";
