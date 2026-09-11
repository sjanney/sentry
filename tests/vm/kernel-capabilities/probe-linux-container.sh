#!/usr/bin/env bash
# Runs the privileged hook probes on the host kernel architecture.
set -euo pipefail

docker run --rm --privileged \
  --pid=host \
  --mount "type=bind,source=$(pwd),target=/work,readonly" \
  --workdir /work \
  --entrypoint /bin/bash \
  rust:1.92-bookworm -ceu '
    apt-get update -qq
    DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends \
      bpftool clang gcc libbpf-dev linux-libc-dev llvm
    case "$(uname -m)" in
      aarch64|arm64)
        target_arch=arm64
        linux_include=/usr/include/aarch64-linux-gnu
        ;;
      x86_64)
        target_arch=x86
        linux_include=/usr/include/x86_64-linux-gnu
        ;;
      *)
        echo "unsupported kernel architecture: $(uname -m)" >&2
        exit 2
        ;;
    esac
    mkdir -p /sys/kernel/security
    mount -t securityfs securityfs /sys/kernel/security 2>/dev/null || true

    printf "kernel="; uname -r
    test -r /sys/kernel/btf/vmlinux && echo "btf=present" || echo "btf=missing"
    test -e /sys/fs/cgroup/cgroup.controllers && echo "cgroup_v2=present" || echo "cgroup_v2=missing"
    awk "/^Seccomp:/{print \"seccomp_mode=\" \$2}" /proc/self/status
    if test -r /sys/kernel/security/lsm; then
      lsm_list=$(cat /sys/kernel/security/lsm)
      printf "lsms=%s\\n" "$lsm_list"
      case ",$lsm_list," in
        *,bpf,*) echo "bpf_lsm=preflight-present" ;;
        *) echo "bpf_lsm=preflight-missing" ;;
      esac
    else
      echo "bpf_lsm=preflight-unknown"
    fi
    gcc -Wall -Wextra -Werror \
      tests/vm/kernel-capabilities/seccomp-self-deny.c \
      -o /tmp/seccomp-self-deny
    /tmp/seccomp-self-deny
    gcc -Wall -Wextra -Werror \
      tests/vm/kernel-capabilities/seccomp-fallback-deny-socket.c \
      -o /tmp/seccomp-fallback-deny-socket
    /tmp/seccomp-fallback-deny-socket
    bpftool btf dump file /sys/kernel/btf/vmlinux format c > /tmp/vmlinux.h
    clang -target bpf -D__TARGET_ARCH_$target_arch -O2 -g \
      -I/tmp -I"$linux_include" \
      -c tests/vm/kernel-capabilities/file-open-deny.bpf.c \
      -o /tmp/file-open-deny.bpf.o
    gcc -Wall -Wextra -Werror tests/vm/kernel-capabilities/file-open-deny-loader.c \
      -lbpf -lelf -lz -o /tmp/file-open-deny-loader
    /tmp/file-open-deny-loader /tmp/file-open-deny.bpf.o
    clang -target bpf -D__TARGET_ARCH_$target_arch -O2 -g \
      -I"$linux_include" \
      -c tests/vm/kernel-capabilities/cgroup-connect-deny.bpf.c \
      -o /tmp/cgroup-connect-deny.bpf.o
    gcc -Wall -Wextra -Werror tests/vm/kernel-capabilities/cgroup-connect-deny-loader.c \
      -lbpf -lelf -lz -o /tmp/cgroup-connect-deny-loader
    /tmp/cgroup-connect-deny-loader /tmp/cgroup-connect-deny.bpf.o
  '
