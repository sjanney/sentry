#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
workdir=$(mktemp -d)
trap 'rm -rf "$workdir"' EXIT

cd "$root"

help=$(cargo run -q -p sentry-cli -- --help)
grep -Fq 'usage: sentry' <<<"$help"

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

if [[ $(uname -s) == Linux ]]; then
  capabilities=$(cargo run -q -p sentry-cli -- capabilities)
  grep -Fq 'kernel: ' <<<"$capabilities"
  grep -Fq 'arch: ' <<<"$capabilities"
  audit_log="$workdir/audit.log"
  cargo run -q -p sentry-cli -- observe --audit-log "$audit_log" -- sh -c 'exit 0'
  audit_result=$(cargo run -q -p sentry-cli -- audit verify "$audit_log")
  grep -Fq 'verified audit sequence 2' <<<"$audit_result"
  if cargo run -q -p sentry-cli -- attach 1 unexpected; then
    echo 'attach accepted unexpected arguments' >&2
    exit 1
  fi
else
  echo 'skipped Linux-only observe CLI flow'
fi

echo 'verified CLI flow'
