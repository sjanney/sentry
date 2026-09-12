#!/usr/bin/env python3
"""Independent SHA-256 verifier for Sentry audit v1 files."""
import hashlib
import sys
from pathlib import Path


def main() -> int:
    if len(sys.argv) not in (2, 4):
        print(
            "usage: verify_audit_log.py PATH [CHECKPOINT_SEQUENCE CHECKPOINT_SHA256]",
            file=sys.stderr,
        )
        return 2
    if len(sys.argv) == 4:
        try:
            sequence = int(sys.argv[2])
        except ValueError:
            print("checkpoint sequence must be a non-negative integer", file=sys.stderr)
            return 2
        if sequence < 0:
            print("checkpoint sequence must be a non-negative integer", file=sys.stderr)
            return 2
        previous = sys.argv[3].lower()
        if len(previous) != 64 or any(c not in "0123456789abcdef" for c in previous):
            print("checkpoint hash must be 64 hexadecimal characters", file=sys.stderr)
            return 2
    else:
        previous = "00" * 32
        sequence = 0
    try:
        lines = Path(sys.argv[1]).read_text(encoding="utf-8").splitlines()
        for number, line in enumerate(lines, 1):
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
    except (OSError, UnicodeError, ValueError) as error:
        print(f"audit verification failed: {error}", file=sys.stderr)
        return 1
    print(f"verified {sequence} audit records")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
