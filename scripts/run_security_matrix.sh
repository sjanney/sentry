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
  if [[ "$machine" == 'aarch64' || "$machine" == 'arm64' || "$machine" == 'x86_64' ]]; then
    bash tests/vm/kernel-capabilities/probe-linux-container.sh
    echo "native $machine cell: passed"
  else
    echo "unsupported native architecture: $machine"
    exit 2
  fi
} | tee "$output"
