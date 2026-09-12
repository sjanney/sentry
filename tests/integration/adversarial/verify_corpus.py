#!/usr/bin/env python3
"""Verify deterministic synthetic adversarial fixtures and a loopback sink."""
import socket
import threading
from pathlib import Path

ROOT = Path(__file__).parent
FIXTURES = ROOT / "fixtures"
MARKER = "SENTRY_SYNTHETIC_SECRET_DO_NOT_USE"


def main() -> int:
    malicious = [FIXTURES / "README.md", FIXTURES / "issue.md", FIXTURES / "tool-description.md"]
    assert all("127.0.0.1:18080" in path.read_text(encoding="utf-8") for path in malicious)
    assert MARKER in (FIXTURES / ".sentry-fixture-secret").read_text(encoding="utf-8")
    assert MARKER not in (FIXTURES / "legitimate-work.txt").read_text(encoding="utf-8")
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sink:
        sink.bind(("127.0.0.1", 0))
        sink.listen(1)
        sink.settimeout(2)
        host, port = sink.getsockname()
        assert host == "127.0.0.1"

        def attempted_exfiltration() -> None:
            with socket.create_connection((host, port), timeout=2) as client:
                client.sendall(MARKER.encode("ascii"))

        attempt = threading.Thread(target=attempted_exfiltration)
        attempt.start()
        connection, _ = sink.accept()
        with connection:
            assert connection.recv(1024) == MARKER.encode("ascii")
        attempt.join(timeout=2)
        assert not attempt.is_alive()
    print("verified adversarial corpus")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
