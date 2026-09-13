// SPDX-License-Identifier: Apache-2.0
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

/* Mirrors sentry_types::EventHeader ABI v1. The daemon owns local sequencing
 * and supplies a redacted target label; this probe supplies only raw kernel
 * identity and timestamp fields. */
struct sentry_event_header {
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
};

#define SENTRY_EVENT_ABI_VERSION 1
#define SENTRY_EVENT_EXEC 1

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 20);
} events SEC(".maps");

SEC("tracepoint/sched/sched_process_exec")
int capture_exec(void *ctx)
{
    struct sentry_event_header *event;
    __u64 pid_tgid;

    event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event)
        return 0;

    pid_tgid = bpf_get_current_pid_tgid();
    event->version = SENTRY_EVENT_ABI_VERSION;
    event->kind = SENTRY_EVENT_EXEC;
    event->flags = 0;
    event->event_size = sizeof(*event);
    event->sequence = 0;
    event->timestamp_ns = bpf_ktime_get_ns();
    event->run_id = 0;
    event->tgid = pid_tgid >> 32;
    event->tid = (__u32)pid_tgid;
    event->parent_tgid = 0;
    event->reserved = 0;
    bpf_ringbuf_submit(event, 0);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
