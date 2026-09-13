#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
workdir=$(mktemp -d)
trap 'rm -rf "$workdir"' EXIT

cd "$root"

help=$(cargo run -q -p sentry-cli -- --help)
grep -Fq 'usage: sentry' <<<"$help"

daemon_info=$(cargo run -q -p sentry-daemon)
grep -Fq 'sentryd ' <<<"$daemon_info"
if [[ $(uname -s) != Linux ]]; then
  grep -Fq 'host: unsupported (Linux required)' <<<"$daemon_info"
fi

candidate=$(cargo run -q -p sentry-cli -- generate \
  --run-id cli-flow --workspace /workspace/demo --domain api.example.test)
grep -Fq 'mode = "dry_run"' <<<"$candidate"
grep -Fq 'api.example.test # observed in runs: cli-flow' <<<"$candidate"

dry_run=$(cargo run -q -p sentry-cli -- dry-run \
  --allow-domain api.example.test --domain api.example.test --secret)
grep -Fq 'would_deny=true' <<<"$dry_run"
grep -Fq 'rule_id=Some(SecretTaintDeny)' <<<"$dry_run"

cidr_dry_run=$(cargo run -q -p sentry-cli -- dry-run \
  --allow-cidr 198.51.100.0/24 --ip 198.51.100.7)
grep -Fq 'would_deny=false' <<<"$cidr_dry_run"

if cargo run -q -p sentry-cli -- dry-run --allow-cidr 198.51.100.0/24; then
  echo 'CIDR dry-run accepted a missing --ip' >&2
  exit 1
fi
if cargo run -q -p sentry-cli -- dry-run --allow-cidr 198.51.100.0/24 --ip invalid; then
  echo 'CIDR dry-run accepted an invalid --ip' >&2
  exit 1
fi
if cargo run -q -p sentry-cli -- audit verify /tmp/sentry-missing-audit \
  --checkpoint-sequence 1; then
  echo 'audit verify accepted an incomplete checkpoint' >&2
  exit 1
fi
if cargo run -q -p sentry-cli -- audit verify /tmp/sentry-missing-audit \
  --checkpoint-sequence 1 --checkpoint-hash invalid; then
  echo 'audit verify accepted a malformed checkpoint hash' >&2
  exit 1
fi
if cargo run -q -p sentry-cli -- audit verify /tmp/sentry-missing-audit \
  --checkpoint-sequence 1 --checkpoint-hash 'éééééééééééééééééééééééééééééé'; then
  echo 'audit verify accepted a non-ASCII checkpoint hash' >&2
  exit 1
fi
checkpoint_log="$workdir/rotated-audit.log"
: > "$checkpoint_log"
checkpoint_result=$(cargo run -q -p sentry-cli -- audit verify "$checkpoint_log" \
  --checkpoint-sequence 7 \
  --checkpoint-hash 0000000000000000000000000000000000000000000000000000000000000000)
grep -Fq 'verified audit sequence 7' <<<"$checkpoint_result"

if [[ $(uname -s) == Linux ]]; then
  capabilities=$(cargo run -q -p sentry-cli -- capabilities)
  grep -Fq 'kernel: ' <<<"$capabilities"
  grep -Fq 'arch: ' <<<"$capabilities"
  audit_log="$workdir/audit.log"
  cargo run -q -p sentry-cli -- observe --audit-log "$audit_log" -- sh -c 'exit 0'
  audit_result=$(cargo run -q -p sentry-cli -- audit verify "$audit_log")
  grep -Fq 'verified audit sequence 2' <<<"$audit_result"
  failed_audit_log="$workdir/failed-audit.log"
  if cargo run -q -p sentry-cli -- observe --audit-log "$failed_audit_log" -- \
    /definitely/not/a/sentry-command; then
    echo 'observe accepted a command that could not spawn' >&2
    exit 1
  fi
  failed_audit_result=$(cargo run -q -p sentry-cli -- audit verify "$failed_audit_log")
  grep -Fq 'verified audit sequence 2' <<<"$failed_audit_result"
  grep -Fq '636f6d6d616e645f737061776e5f6661696c6564' "$failed_audit_log"
  if cargo run -q -p sentry-cli -- attach 1 unexpected; then
    echo 'attach accepted unexpected arguments' >&2
    exit 1
  fi
  fallback_output=$(cargo run -q -p sentry-cli -- enforce \
    --policy examples/seccomp-socket-deny.json -- python3 -c '
import errno
import socket

try:
    socket.socket()
except PermissionError as error:
    raise SystemExit(0 if error.errno == errno.EPERM else 2)
raise SystemExit(3)
' 2>&1)
  grep -Fq 'enforcement_path=seccomp_socket_deny scope=socket(2)_only' \
    <<<"$fallback_output"
  if cargo run -q -p sentry-cli -- enforce \
    --policy examples/policy-v0.json -- sh -c 'exit 99'; then
    echo 'seccomp fallback accepted a policy outside its bounded input schema' >&2
    exit 1
  fi
else
  echo 'skipped Linux-only observe CLI flow'
fi

echo 'verified CLI flow'
