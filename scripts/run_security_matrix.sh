#!/usr/bin/env bash
# Runs a native security-matrix cell and writes reproducible evidence.
set -euo pipefail

output=${SENTRY_MATRIX_OUTPUT:-artifacts/security-matrix-$(uname -m).md}
mkdir -p "$(dirname "$output")"
machine=$(uname -m)
kernel=$(uname -r)
expected_arch=$machine
if [[ "$expected_arch" == 'arm64' ]]; then
  expected_arch=aarch64
fi
{
  echo '# Security matrix result'
  echo
  printf '%s\n' "- runner OS: \`$(uname -s)\`"
  printf '%s\n' "- runner architecture: \`$machine\`"
  printf '%s\n' "- runner kernel: \`$kernel\`"
  printf '%s\n' "- probe architecture expectation: \`$expected_arch\`"
  echo '- primary mode: privileged BPF LSM and cgroup probe'
  echo '- fallback mode: seccomp socket-deny probe'
  echo
  echo '## Coverage cells'
  echo '| cell | status | reason |'
  echo '|---|---|---|'
  echo '| container kernel probes | running | BPF LSM, cgroup, and seccomp checks below |'
  echo '| launch enforcement | unsupported | CLI launch is not wired to policy maps |'
  echo '| attach enforcement | unsupported | attach path is observation-only |'
  echo '| adversarial workload | unsupported | live event ingestion and audit emission are not wired |'
  echo '| legitimate workload | unsupported | live event ingestion and audit emission are not wired |'
  echo
  echo '## Result'
  if [[ "$machine" == 'aarch64' || "$machine" == 'arm64' || "$machine" == 'x86_64' ]]; then
    SENTRY_EXPECT_ARCH="$expected_arch" bash tests/vm/kernel-capabilities/probe-linux-container.sh
    echo "container $expected_arch cell: passed"
  else
    echo "unsupported runner architecture: $machine"
    exit 2
  fi
} | tee "$output"
