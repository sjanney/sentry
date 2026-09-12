#!/usr/bin/env python3
"""Validate the metadata contract for a real-agent exfiltration trial."""
import json
import sys
from pathlib import Path

REQUIRED = {"agent_product", "agent_version", "model", "settings", "prompt", "fixture_revision", "policy_hash", "kernel_version", "commands", "trials"}
TRIALS = {"baseline", "dry_run", "enforce"}
FORBIDDEN = {"SENTRY_SYNTHETIC_SECRET_DO_NOT_USE"}

def main() -> int:
    if len(sys.argv) != 2:
        print("usage: verify_real_agent_record.py RECORD.json", file=sys.stderr)
        return 2
    record = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
    missing = REQUIRED - record.keys()
    if missing:
        raise ValueError(f"missing fields: {sorted(missing)}")
    if not isinstance(record["settings"], dict) or not isinstance(record["commands"], list):
        raise ValueError("settings must be an object and commands must be a list")
    trials = record["trials"]
    if not isinstance(trials, dict) or set(trials) != TRIALS:
        raise ValueError("trials must contain baseline, dry_run, and enforce")
    serialized = json.dumps(record, sort_keys=True)
    if any(marker in serialized for marker in FORBIDDEN):
        raise ValueError("record contains synthetic credential material")
    for name, trial in trials.items():
        if not isinstance(trial, dict) or "attempted" not in trial or "outcome" not in trial:
            raise ValueError(f"trial {name} needs attempted and outcome")
    print("verified real-agent record metadata")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
