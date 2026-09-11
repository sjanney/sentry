#!/usr/bin/env python3
import json
import sys
from pathlib import Path


def decide(case: dict) -> str:
    taint = set(case["taint"])
    policy = case["policy"]
    destination = case["destination"]

    if "secret" in taint:
        return "deny_secret_taint"
    if "untrusted_input" in taint and policy["deny_untrusted_egress"]:
        return "deny_untrusted_taint"
    if policy["allowed_domains"]:
        attributed = (
            destination["dns_observed"]
            and destination["ttl_valid"]
            and destination["same_domain"]
            and destination["domain"] in policy["allowed_domains"]
        )
        if not attributed:
            return "deny_unattributed_destination"
    return "allow"


def main() -> int:
    case_path = Path(__file__).with_name("ifc-egress-cases.json")
    cases = json.loads(case_path.read_text())
    failures = []
    for case in cases:
        actual = decide(case)
        if actual != case["expected"]:
            failures.append(f'{case["name"]}: expected {case["expected"]}, got {actual}')
    if failures:
        print("\n".join(failures), file=sys.stderr)
        return 1
    print(f"verified {len(cases)} information-flow egress cases")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
