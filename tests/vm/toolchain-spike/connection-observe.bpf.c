// SPDX-License-Identifier: Apache-2.0
#include <linux/bpf.h>
#include <linux/in.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#define SENTRY_EVENT_ABI_VERSION 1
#define SENTRY_EVENT_CONNECT 5
#define SENTRY_FAMILY_IPV4 4
#define SENTRY_FAMILY_IPV6 6

/* Mirrors sentry_types::ConnectEvent. Destination bytes remain in network
 * order. The daemon owns run attribution and DNS correlation. */
struct connect_event {
    __u16 version;
    __u8 kind;
    __u8 flags;
    __u32 event_size;
    __u64 sequence;
    __u64 timestamp_ns;
    __u64 run_id;
    __u32 tgid;
    __u32 tid;
    __u32 parent_tgid;
    __u32 reserved;
    __u8 family;
    __u8 protocol;
    __u16 payload_reserved;
    __u16 port;
    __u16 address_reserved;
    __u8 address[16];
};

_Static_assert(sizeof(struct connect_event) == 72,
               "Sentry connect event must remain 72 bytes");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 20);
} events SEC(".maps");

static __always_inline struct connect_event *reserve_event(
    struct bpf_sock_addr *ctx, __u8 family)
{
    struct connect_event *event;
    __u64 pid_tgid;

    if (ctx->protocol != IPPROTO_TCP && ctx->protocol != IPPROTO_UDP)
        return 0;
    event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event)
        return 0;
    pid_tgid = bpf_get_current_pid_tgid();
    event->version = SENTRY_EVENT_ABI_VERSION;
    event->kind = SENTRY_EVENT_CONNECT;
    event->flags = 0;
    event->event_size = sizeof(*event);
    event->sequence = 0;
    event->timestamp_ns = bpf_ktime_get_ns();
    event->run_id = 0;
    event->tgid = pid_tgid >> 32;
    event->tid = (__u32)pid_tgid;
    event->parent_tgid = 0;
    event->reserved = 0;
    event->family = family;
    event->protocol = ctx->protocol;
    event->payload_reserved = 0;
    event->port = bpf_ntohs(ctx->user_port);
    event->address_reserved = 0;
    __builtin_memset(event->address, 0, sizeof(event->address));
    return event;
}

SEC("cgroup/connect4")
int observe_connect4(struct bpf_sock_addr *ctx)
{
    struct connect_event *event = reserve_event(ctx, SENTRY_FAMILY_IPV4);

    if (!event)
        return 1;
    __builtin_memcpy(event->address, &ctx->user_ip4, sizeof(ctx->user_ip4));
    bpf_ringbuf_submit(event, 0);
    return 1;
}

SEC("cgroup/connect6")
int observe_connect6(struct bpf_sock_addr *ctx)
{
    struct connect_event *event = reserve_event(ctx, SENTRY_FAMILY_IPV6);

    if (!event)
        return 1;
    __builtin_memcpy(event->address, ctx->user_ip6, sizeof(ctx->user_ip6));
    bpf_ringbuf_submit(event, 0);
    return 1;
}

char LICENSE[] SEC("license") = "GPL";
