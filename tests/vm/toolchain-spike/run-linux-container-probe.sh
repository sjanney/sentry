#!/usr/bin/env bash
# Runs a disposable Linux toolchain probe on the native kernel architecture.
set -euo pipefail

docker run --rm --privileged -e SENTRY_EXPECT_ARCH \
  --mount "type=bind,source=$(pwd),target=/work,readonly" \
  --workdir /work \
  --entrypoint /bin/bash \
  rust:1.92-bookworm -ceu '
    apt-get update -qq
    DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends \
      bpftool ca-certificates clang gcc libbpf-dev linux-libc-dev llvm

    mkdir -p /sys/kernel/security /sys/kernel/tracing
    mount -t securityfs securityfs /sys/kernel/security 2>/dev/null || true
    mount -t tracefs tracefs /sys/kernel/tracing 2>/dev/null || true
    printf "kernel: "; uname -r
    printf "arch: "; uname -m
    if test -n "${SENTRY_EXPECT_ARCH:-}" && test "${SENTRY_EXPECT_ARCH}" != "$(uname -m)"; then
      echo "unexpected architecture: expected ${SENTRY_EXPECT_ARCH}, got $(uname -m)" >&2
      exit 2
    fi
    test -r /sys/kernel/btf/vmlinux && echo "BTF: present"
    test -e /sys/fs/cgroup/cgroup.controllers && echo "cgroup: v2"
    printf "LSMs: "; cat /sys/kernel/security/lsm
    for lifecycle_event in exec fork exit; do
      test -e "/sys/kernel/tracing/events/sched/sched_process_${lifecycle_event}/id"
    done

    case "$(uname -m)" in
      aarch64|arm64) linux_include=/usr/include/aarch64-linux-gnu ;;
      x86_64) linux_include=/usr/include/x86_64-linux-gnu ;;
      *) echo "unsupported kernel architecture: $(uname -m)" >&2; exit 2 ;;
    esac

    clang -target bpf -O2 -g -I"$linux_include" -c \
      tests/vm/toolchain-spike/tracepoint-ringbuf.bpf.c \
      -o /tmp/tracepoint-ringbuf.bpf.o
    clang -target bpf -O2 -g -I"$linux_include" -c \
      tests/vm/toolchain-spike/connection-observe.bpf.c \
      -o /tmp/connection-observe.bpf.o
    gcc -Wall -Wextra -Werror tests/vm/toolchain-spike/connection-client.c \
      -o /tmp/connection-client
    bpftool btf dump file /sys/kernel/btf/vmlinux format c > /tmp/vmlinux.h
    case "$(uname -m)" in
      aarch64|arm64) target_arch=arm64 ;;
      x86_64) target_arch=x86 ;;
    esac
    clang -target bpf -D__TARGET_ARCH_$target_arch -O2 -g \
      -I/tmp -I"$linux_include" \
      -c tests/vm/toolchain-spike/filesystem-observe.bpf.c \
      -o /tmp/filesystem-observe.bpf.o
    CARGO_TARGET_DIR=/tmp/sentry-aya-probe-target \
      cargo run --locked --quiet --manifest-path tests/vm/toolchain-spike/aya-loader/Cargo.toml \
      -- /tmp/tracepoint-ringbuf.bpf.o
    CARGO_TARGET_DIR=/tmp/sentry-libbpf-rs-probe-target \
      cargo run --locked --quiet --manifest-path tests/vm/toolchain-spike/libbpf-rs-loader/Cargo.toml \
      -- /tmp/tracepoint-ringbuf.bpf.o

    CARGO_TARGET_DIR=/tmp/sentry-daemon-runtime-target \
      cargo build --locked --quiet -p sentry-daemon
    /tmp/sentry-daemon-runtime-target/debug/sentryd \
      capture-lifecycle /tmp/tracepoint-ringbuf.bpf.o 1000 \
      > /tmp/sentryd-capture.log &
    capture_pid=$!
    for attempt in 1 2 3 4 5 6 7 8 9 10; do
      grep -q "capture-lifecycle: ready" /tmp/sentryd-capture.log && break
      sleep 0.1
    done
    grep -q "capture-lifecycle: ready" /tmp/sentryd-capture.log
    /bin/true
    wait "$capture_pid"
    cat /tmp/sentryd-capture.log
    grep -Eq "accepted=[1-9][0-9]*" /tmp/sentryd-capture.log
    grep -Eq "exec=[1-9][0-9]*" /tmp/sentryd-capture.log
    grep -Eq "fork=[1-9][0-9]*" /tmp/sentryd-capture.log
    grep -Eq "exit=[1-9][0-9]*" /tmp/sentryd-capture.log

    fixture=/tmp/sentry-filesystem-fixture
    mkdir -p "$fixture/.ssh" "$fixture/.aws" "$fixture/keyring" \
      "$fixture/token-cache"
    for fixture_file in \
      "$fixture/.ssh/id_test" \
      "$fixture/.aws/credentials" \
      "$fixture/.env" \
      "$fixture/keyring/store" \
      "$fixture/token-cache/session"; do
      printf synthetic > "$fixture_file"
    done
    ln "$fixture/.ssh/id_test" "$fixture/ssh-hardlink"
    ln -s "$fixture/.aws/credentials" "$fixture/cloud-symlink"
    /tmp/sentry-daemon-runtime-target/debug/sentryd capture-filesystem \
      /tmp/filesystem-observe.bpf.o 2000 \
      "ssh_key=$fixture/.ssh/id_test" \
      "cloud_credential=$fixture/.aws/credentials" \
      "dotenv=$fixture/.env" \
      "keyring=$fixture/keyring/store" \
      "token_cache=$fixture/token-cache/session" \
      > /tmp/sentryd-filesystem.log &
    filesystem_pid=$!
    for attempt in 1 2 3 4 5 6 7 8 9 10; do
      grep -q "capture-filesystem: ready" /tmp/sentryd-filesystem.log && break
      sleep 0.1
    done
    grep -q "capture-filesystem: ready" /tmp/sentryd-filesystem.log
    cat "$fixture/.ssh/id_test" >/dev/null
    cat "$fixture/ssh-hardlink" >/dev/null
    cat "$fixture/cloud-symlink" >/dev/null
    mv "$fixture/.env" "$fixture/.env.renamed"
    cat "$fixture/.env.renamed" >/dev/null
    cat "$fixture/keyring/store" >/dev/null
    mkdir "$fixture/ns-target"
    unshare --mount /bin/sh -ceu \
      "mount --bind $fixture/token-cache $fixture/ns-target; cat $fixture/ns-target/session >/dev/null"
    wait "$filesystem_pid"
    cat /tmp/sentryd-filesystem.log
    grep -Eq "attempted=[1-9][0-9]*" /tmp/sentryd-filesystem.log
    grep -Eq "succeeded=[1-9][0-9]*" /tmp/sentryd-filesystem.log
    grep -Eq "dropped=0 malformed=0" /tmp/sentryd-filesystem.log
    for class in ssh_key cloud_credential dotenv keyring token_cache; do
      grep -q "class=$class " /tmp/sentryd-filesystem.log
    done
    if grep -Eq "sentry-filesystem-fixture|synthetic" /tmp/sentryd-filesystem.log; then
      echo "filesystem observation leaked a fixture path or content" >&2
      exit 1
    fi

    /tmp/sentry-daemon-runtime-target/debug/sentryd capture-connections \
      /tmp/connection-observe.bpf.o /sys/fs/cgroup 1500 \
      > /tmp/sentryd-connections.log &
    connection_pid=$!
    for attempt in 1 2 3 4 5 6 7 8 9 10; do
      grep -q "capture-connections: ready" /tmp/sentryd-connections.log && break
      sleep 0.1
    done
    grep -q "capture-connections: ready" /tmp/sentryd-connections.log
    /tmp/connection-client
    wait "$connection_pid"
    cat /tmp/sentryd-connections.log
    grep -Eq "tcp=[1-9][0-9]* udp=[1-9][0-9]*" /tmp/sentryd-connections.log
    grep -Eq "ipv4=[1-9][0-9]* ipv6=[1-9][0-9]*" /tmp/sentryd-connections.log
    grep -Eq "unknown=[1-9][0-9]* correlated=0" /tmp/sentryd-connections.log
    grep -Eq "dropped=0 malformed=0" /tmp/sentryd-connections.log
  '
