#!/usr/bin/env bash
# Runs a native security-matrix cell and writes reproducible evidence.
set -euo pipefail

output=${SENTRY_MATRIX_OUTPUT:-artifacts/security-matrix-$(uname -m).md}
mkdir -p "$(dirname "$output")"
machine=$(uname -m)
kernel=$(uname -r)
{
  echo '# Native security matrix result'
  echo
  printf '%s\n' "- machine: \`$machine\`"
  printf '%s\n' "- kernel: \`$kernel\`"
  echo '- primary mode: privileged BPF LSM and cgroup probe'
  echo '- fallback mode: seccomp socket-deny probe'
  echo
  echo '## Result'
  if [[ "$machine" == 'aarch64' || "$machine" == 'arm64' ]]; then
    bash tests/vm/kernel-capabilities/probe-arm64-container.sh
    echo 'native arm64 cell: passed'
  elif [[ "$machine" == 'x86_64' ]]; then
    echo 'x86_64 native probe: unsupported until an x86 BPF compile and runtime probe are added'
    exit 2
  else
    echo "unsupported native architecture: $machine"
    exit 2
  fi
} | tee "$output"
