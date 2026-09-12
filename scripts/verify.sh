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
bash tests/integration/verify_cli_flow.sh
