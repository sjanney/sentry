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
#define SENTRY_EVENT_FORK 2
#define SENTRY_EVENT_EXIT 3

_Static_assert(sizeof(struct sentry_event_header) == 48,
               "Sentry event ABI v1 header must remain 48 bytes");

/* Stable sched_process_fork tracepoint fields from tracefs format. The child
 * value is a task ID; this tracepoint does not expose a trustworthy child TGID
 * or start time, so the event leaves child TGID and run attribution unknown. */
struct sched_process_fork_args {
    __u64 common;
    char parent_comm[16];
    __s32 parent_pid;
    char child_comm[16];
    __s32 child_pid;
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 20);
} events SEC(".maps");

static __always_inline int emit_process_event(__u8 kind, __u32 tgid,
                                               __u32 tid,
                                               __u32 parent_tgid)
{
    struct sentry_event_header *event;

    event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event)
        return 0;

    event->version = SENTRY_EVENT_ABI_VERSION;
    event->kind = kind;
    event->flags = 0;
    event->event_size = sizeof(*event);
    event->sequence = 0;
    event->timestamp_ns = bpf_ktime_get_ns();
    event->run_id = 0;
    event->tgid = tgid;
    event->tid = tid;
    event->parent_tgid = parent_tgid;
    event->reserved = 0;
    bpf_ringbuf_submit(event, 0);
    return 0;
}

SEC("tracepoint/sched/sched_process_exec")
int capture_exec(void *ctx)
{
    __u64 pid_tgid;

    (void)ctx;
    pid_tgid = bpf_get_current_pid_tgid();
    return emit_process_event(SENTRY_EVENT_EXEC, pid_tgid >> 32,
                              (__u32)pid_tgid, 0);
}

SEC("tracepoint/sched/sched_process_fork")
int capture_fork(struct sched_process_fork_args *ctx)
{
    __u64 parent_pid_tgid = bpf_get_current_pid_tgid();

    return emit_process_event(SENTRY_EVENT_FORK, 0, (__u32)ctx->child_pid,
                              parent_pid_tgid >> 32);
}

SEC("tracepoint/sched/sched_process_exit")
int capture_exit(void *ctx)
{
    __u64 pid_tgid;

    (void)ctx;
    pid_tgid = bpf_get_current_pid_tgid();
    return emit_process_event(SENTRY_EVENT_EXIT, pid_tgid >> 32,
                              (__u32)pid_tgid, 0);
}

char LICENSE[] SEC("license") = "GPL";
