// SPDX-License-Identifier: Apache-2.0
#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define SENTRY_EVENT_ABI_VERSION 1
#define SENTRY_EVENT_FILE_OPEN 4
#define SENTRY_FILE_ATTEMPTED 1
#define SENTRY_FILE_SUCCEEDED 2
#define SENTRY_FILE_DENIED 3

#if defined(__TARGET_ARCH_arm64)
#define SENTRY_NR_OPENAT 56
#define SENTRY_NR_OPENAT2 437
#elif defined(__TARGET_ARCH_x86)
#define SENTRY_NR_OPEN 2
#define SENTRY_NR_OPENAT 257
#define SENTRY_NR_OPENAT2 437
#else
#error "filesystem observation supports arm64 and x86_64"
#endif

struct file_rule_key {
    __u64 device;
    __u64 inode;
};

struct pending_file_open {
    struct file_rule_key identity;
    __u8 credential_class;
    __u8 reserved[7];
};

/* Mirrors sentry_types::FileOpenEvent's 72-byte wire encoding. There is no
 * pathname or content field in this record. */
struct file_open_event {
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
    __u8 credential_class;
    __u8 status;
    __u16 payload_reserved;
    __s32 error_number;
    __u64 device;
    __u64 inode;
};

_Static_assert(sizeof(struct file_open_event) == 72,
               "Sentry file-open event must remain 72 bytes");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 64);
    __type(key, struct file_rule_key);
    __type(value, __u8);
} credential_inodes SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 4096);
    __type(key, __u64);
    __type(value, __u8);
} open_calls SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 4096);
    __type(key, __u64);
    __type(value, struct pending_file_open);
} pending_opens SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 20);
} events SEC(".maps");

static __always_inline int emit_file_event(
    const struct pending_file_open *pending, __u8 status, __s32 error_number)
{
    struct file_open_event *event;
    __u64 pid_tgid = bpf_get_current_pid_tgid();

    event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event)
        return 0;
    event->version = SENTRY_EVENT_ABI_VERSION;
    event->kind = SENTRY_EVENT_FILE_OPEN;
    event->flags = 0;
    event->event_size = sizeof(*event);
    event->sequence = 0;
    event->timestamp_ns = bpf_ktime_get_ns();
    event->run_id = 0;
    event->tgid = pid_tgid >> 32;
    event->tid = (__u32)pid_tgid;
    event->parent_tgid = 0;
    event->reserved = 0;
    event->credential_class = pending->credential_class;
    event->status = status;
    event->payload_reserved = 0;
    event->error_number = error_number;
    event->device = pending->identity.device;
    event->inode = pending->identity.inode;
    bpf_ringbuf_submit(event, 0);
    return 0;
}

SEC("raw_tracepoint/sys_enter")
int capture_open_enter(struct bpf_raw_tracepoint_args *ctx)
{
    __u64 *arguments = (__u64 *)ctx;
    __u64 syscall_number = arguments[1];
    __u64 pid_tgid;
    __u8 marker = 1;

    if (syscall_number != SENTRY_NR_OPENAT &&
        syscall_number != SENTRY_NR_OPENAT2
#if defined(SENTRY_NR_OPEN)
        && syscall_number != SENTRY_NR_OPEN
#endif
    )
        return 0;
    pid_tgid = bpf_get_current_pid_tgid();
    bpf_map_update_elem(&open_calls, &pid_tgid, &marker, BPF_ANY);
    return 0;
}

SEC("lsm/file_open")
int BPF_PROG(capture_credential_open, struct file *file, int ret)
{
    struct pending_file_open pending = {};
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u8 *credential_class;

    if (!bpf_map_lookup_elem(&open_calls, &pid_tgid))
        return ret;
    pending.identity.device = BPF_CORE_READ(file, f_inode, i_sb, s_dev);
    pending.identity.inode = BPF_CORE_READ(file, f_inode, i_ino);
    credential_class = bpf_map_lookup_elem(&credential_inodes,
                                           &pending.identity);
    if (!credential_class)
        return ret;
    pending.credential_class = *credential_class;
    if (bpf_map_update_elem(&pending_opens, &pid_tgid, &pending, BPF_ANY))
        return ret;
    emit_file_event(&pending, SENTRY_FILE_ATTEMPTED, 0);
    return ret;
}

SEC("raw_tracepoint/sys_exit")
int capture_open_exit(struct bpf_raw_tracepoint_args *ctx)
{
    __u64 *arguments = (__u64 *)ctx;
    __s64 result = (__s64)arguments[1];
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    struct pending_file_open *stored;
    struct pending_file_open pending;

    bpf_map_delete_elem(&open_calls, &pid_tgid);
    stored = bpf_map_lookup_elem(&pending_opens, &pid_tgid);
    if (!stored)
        return 0;
    pending = *stored;
    bpf_map_delete_elem(&pending_opens, &pid_tgid);
    if (result < 0)
        emit_file_event(&pending, SENTRY_FILE_DENIED, (__s32)-result);
    else
        emit_file_event(&pending, SENTRY_FILE_SUCCEEDED, 0);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
