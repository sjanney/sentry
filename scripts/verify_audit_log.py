#!/usr/bin/env python3
"""Independent SHA-256 verifier for Sentry audit v1 files."""
import hashlib
import sys
from pathlib import Path


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: verify_audit_log.py PATH", file=sys.stderr)
        return 2
    previous = "00" * 32
    sequence = 0
    for number, line in enumerate(Path(sys.argv[1]).read_text(encoding="utf-8").splitlines(), 1):
        fields = line.split("|")
        if len(fields) != 10 or fields[0] != "v1":
            raise ValueError(f"line {number}: malformed")
        current = int(fields[1])
        if current <= sequence or fields[8] != previous:
            raise ValueError(f"line {number}: sequence or previous hash")
        body = "|".join(fields[:-1])
        digest = hashlib.sha256(body.encode()).hexdigest()
        if fields[-1] != digest:
            raise ValueError(f"line {number}: hash")
        previous, sequence = digest, current
    print(f"verified {sequence} audit records")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
