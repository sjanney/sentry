#!/usr/bin/env bash
# Runs a disposable Linux toolchain probe on the native kernel architecture.
set -euo pipefail

docker run --rm --privileged \
  --mount "type=bind,source=$(pwd),target=/work,readonly" \
  --workdir /work \
  --entrypoint /bin/bash \
  rust:1.92-bookworm -ceu '
    apt-get update -qq
    DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends \
      ca-certificates clang libbpf-dev linux-libc-dev llvm

    mkdir -p /sys/kernel/security /sys/kernel/tracing
    mount -t securityfs securityfs /sys/kernel/security 2>/dev/null || true
    mount -t tracefs tracefs /sys/kernel/tracing 2>/dev/null || true
    printf "kernel: "; uname -r
    printf "arch: "; uname -m
    test -r /sys/kernel/btf/vmlinux && echo "BTF: present"
    test -e /sys/fs/cgroup/cgroup.controllers && echo "cgroup: v2"
    printf "LSMs: "; cat /sys/kernel/security/lsm
    test -e /sys/kernel/tracing/events/sched/sched_process_exec/id

    case "$(uname -m)" in
      aarch64|arm64) linux_include=/usr/include/aarch64-linux-gnu ;;
      x86_64) linux_include=/usr/include/x86_64-linux-gnu ;;
      *) echo "unsupported kernel architecture: $(uname -m)" >&2; exit 2 ;;
    esac

    clang -target bpf -O2 -g -I"$linux_include" -c \
      tests/vm/toolchain-spike/tracepoint-ringbuf.bpf.c \
      -o /tmp/tracepoint-ringbuf.bpf.o
    CARGO_TARGET_DIR=/tmp/sentry-aya-probe-target \
      cargo run --locked --quiet --manifest-path tests/vm/toolchain-spike/aya-loader/Cargo.toml \
      -- /tmp/tracepoint-ringbuf.bpf.o
    CARGO_TARGET_DIR=/tmp/sentry-libbpf-rs-probe-target \
      cargo run --locked --quiet --manifest-path tests/vm/toolchain-spike/libbpf-rs-loader/Cargo.toml \
      -- /tmp/tracepoint-ringbuf.bpf.o
  '
