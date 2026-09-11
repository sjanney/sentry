#!/usr/bin/env bash
# Compiles the shared BPF object and both userspace loaders in Linux.
set -euo pipefail

docker run --rm \
  --mount "type=bind,source=$(pwd),target=/work,readonly" \
  --workdir /work \
  --entrypoint /bin/bash \
  rust:1.92-bookworm -ceu '
    apt-get update -qq
    DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends \
      ca-certificates clang libbpf-dev linux-libc-dev llvm
    case "$(dpkg --print-architecture)" in
      amd64) arch_include=/usr/include/x86_64-linux-gnu ;;
      arm64) arch_include=/usr/include/aarch64-linux-gnu ;;
      *) echo "unsupported Debian architecture" >&2; exit 1 ;;
    esac
    clang -target bpf -O2 -g -I"$arch_include" -c \
      tests/vm/toolchain-spike/tracepoint-ringbuf.bpf.c \
      -o /tmp/tracepoint-ringbuf.bpf.o
    CARGO_TARGET_DIR=/tmp/sentry-workspace-target cargo build --workspace
    CARGO_TARGET_DIR=/tmp/sentry-aya-probe-target \
      cargo build --locked --manifest-path tests/vm/toolchain-spike/aya-loader/Cargo.toml
    CARGO_TARGET_DIR=/tmp/sentry-libbpf-rs-probe-target \
      cargo build --locked --manifest-path tests/vm/toolchain-spike/libbpf-rs-loader/Cargo.toml
  '
