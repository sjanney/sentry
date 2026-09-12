#!/usr/bin/env bash
# Runs every host-safe verification check used by CI.
set -euo pipefail

cargo fmt --check
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
python3 tests/semantics/verify_ifc_egress_cases.py
python3 tests/semantics/verify_policy_v0.py
python3 tests/integration/adversarial/verify_corpus.py
python3 tests/integration/adversarial/verify_real_agent_record.py \
  tests/integration/adversarial/real-agent-record.example.json
audit_fixture=$(mktemp)
trap 'rm -f "$audit_fixture"' EXIT
python3 scripts/verify_audit_log.py "$audit_fixture"
if python3 scripts/verify_audit_log.py "$audit_fixture" invalid 00; then
  echo 'audit verifier accepted an invalid checkpoint sequence' >&2
  exit 1
fi
bash tests/integration/verify_cli_flow.sh
