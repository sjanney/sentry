#!/usr/bin/env bash
# Runs every host-safe verification check used by CI.
set -euo pipefail

cargo fmt --check
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
python3 tests/semantics/verify_ifc_egress_cases.py
