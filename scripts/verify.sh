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
python3 - "$audit_fixture" <<'PY'
import hashlib
import sys

body = "v1|1|72|1|0000000000000000|64|-|74|" + "00" * 32
with open(sys.argv[1], "w", encoding="utf-8") as output:
    output.write(f"{body}|{hashlib.sha256(body.encode()).hexdigest()}\n")
PY
python3 scripts/verify_audit_log.py "$audit_fixture" | grep -Fq 'verified 1 audit records'
if python3 scripts/verify_audit_log.py "$audit_fixture" invalid 00; then
  echo 'audit verifier accepted an invalid checkpoint sequence' >&2
  exit 1
fi
bash tests/integration/verify_cli_flow.sh
