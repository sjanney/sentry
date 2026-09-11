#!/usr/bin/env python3
"""Validate the normative v0 policy fixture without a generator dependency."""
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
POLICY = ROOT / "examples/policy-v0.json"
TOP_LEVEL = {"schema_version", "mode", "default_action", "workspace", "credential_classes", "destinations", "taint", "required_capabilities"}
CREDENTIALS = {"ssh_key", "cloud_credential", "dotenv", "keyring", "token_cache"}
CAPABILITIES = {"bpf_lsm", "cgroup_v2", "dns_observation"}


def validate(policy: object) -> str | None:
    if not isinstance(policy, dict):
        return "POLICY_INVALID_VALUE"
    if set(policy) - TOP_LEVEL:
        return "POLICY_UNKNOWN_FIELD"
    if set(policy) != TOP_LEVEL:
        return "POLICY_MISSING_FIELD"
    if policy["schema_version"] != 1:
        return "POLICY_UNSUPPORTED_SCHEMA"
    if policy["mode"] not in {"dry_run", "enforce"} or policy["default_action"] != "deny":
        return "POLICY_INVALID_VALUE"
    workspace = policy["workspace"]
    destinations = policy["destinations"]
    taint = policy["taint"]
    if not isinstance(workspace, dict) or not isinstance(workspace.get("roots"), list) or not workspace["roots"]:
        return "POLICY_INVALID_VALUE"
    if not isinstance(destinations, dict) or set(destinations) != {"allowed_domains", "allowed_cidrs"}:
        return "POLICY_INVALID_VALUE"
    if not isinstance(destinations["allowed_domains"], list) or not isinstance(destinations["allowed_cidrs"], list):
        return "POLICY_INVALID_VALUE"
    if not isinstance(taint, dict) or set(taint) != {"secret", "untrusted_input"}:
        return "POLICY_INVALID_VALUE"
    if taint["secret"] != "deny" or taint["untrusted_input"] not in {"audit", "deny"}:
        return "POLICY_INVALID_VALUE"
    credentials = policy["credential_classes"]
    capabilities = policy["required_capabilities"]
    if not isinstance(credentials, list) or not all(isinstance(item, str) for item in credentials):
        return "POLICY_INVALID_VALUE"
    if not isinstance(capabilities, list) or not all(isinstance(item, str) for item in capabilities):
        return "POLICY_INVALID_VALUE"
    if not set(credentials).issubset(CREDENTIALS) or not set(capabilities).issubset(CAPABILITIES):
        return "POLICY_INVALID_VALUE"
    return None


def assert_error(policy: object, expected: str) -> None:
    actual = validate(policy)
    assert actual == expected, (actual, expected)


def main() -> int:
    policy = json.loads(POLICY.read_text(encoding="utf-8"))
    assert validate(policy) is None
    assert_error({**policy, "unexpected": True}, "POLICY_UNKNOWN_FIELD")
    assert_error({key: value for key, value in policy.items() if key != "mode"}, "POLICY_MISSING_FIELD")
    assert_error({**policy, "schema_version": 2}, "POLICY_UNSUPPORTED_SCHEMA")
    assert_error({**policy, "default_action": "allow"}, "POLICY_INVALID_VALUE")
    assert_error({**policy, "credential_classes": 1}, "POLICY_INVALID_VALUE")
    print("verified policy v0 fixture and validation errors")
    return 0


if __name__ == "__main__":
    sys.exit(main())
