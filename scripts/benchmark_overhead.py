#!/usr/bin/env python3
"""Measure Sentry command-wrapper overhead on Linux and write raw JSON."""
# SPDX-License-Identifier: Apache-2.0
import json
import os
import platform
import resource
import statistics
import subprocess
import sys
import time
from pathlib import Path

REPETITIONS = 20
WARMUPS = 5
SYSCALL_WORKLOAD = ["python3", "-c", "import os; [os.stat('/dev/null') for _ in range(50_000)]"]


def usage_seconds() -> float:
    usage = resource.getrusage(resource.RUSAGE_CHILDREN)
    return usage.ru_utime + usage.ru_stime


def sample(command: list[str]) -> dict[str, float]:
    before_cpu = usage_seconds()
    before_wall = time.perf_counter_ns()
    subprocess.run(command, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return {"wall_ms": (time.perf_counter_ns() - before_wall) / 1_000_000,
            "cpu_ms": (usage_seconds() - before_cpu) * 1_000}


def summarize(samples: list[dict[str, float]]) -> dict[str, float]:
    def values(metric: str) -> list[float]:
        return [item[metric] for item in samples]

    def p95(values_: list[float]) -> float:
        return sorted(values_)[round(0.95 * (len(values_) - 1))]

    return {"mean_wall_ms": statistics.mean(values("wall_ms")),
            "mean_cpu_ms": statistics.mean(values("cpu_ms")),
            "stdev_wall_ms": statistics.stdev(values("wall_ms")),
            "stdev_cpu_ms": statistics.stdev(values("cpu_ms")),
            "p95_wall_ms": p95(values("wall_ms")), "p95_cpu_ms": p95(values("cpu_ms"))}


def measure(name: str, direct: list[str], wrapped: list[str]) -> dict[str, object]:
    for _ in range(WARMUPS):
        sample(direct)
        sample(wrapped)
    baseline = [sample(direct) for _ in range(REPETITIONS)]
    observed = [sample(wrapped) for _ in range(REPETITIONS)]
    baseline_summary = summarize(baseline)
    observed_summary = summarize(observed)
    baseline_cpu = baseline_summary["mean_cpu_ms"]
    overhead = None if baseline_cpu == 0 else 100 * (observed_summary["mean_cpu_ms"] - baseline_cpu) / baseline_cpu
    p95_cpu_delta = observed_summary["p95_cpu_ms"] - baseline_summary["p95_cpu_ms"]
    p95_wall_delta = observed_summary["p95_wall_ms"] - baseline_summary["p95_wall_ms"]
    return {"workload": name, "baseline": baseline, "sentry": observed,
            "baseline_summary": baseline_summary, "sentry_summary": observed_summary,
            "p95_cpu_delta_ms": p95_cpu_delta, "p95_wall_delta_ms": p95_wall_delta,
            "cpu_overhead_percent": overhead, "cpu_gate_passed": overhead is not None and overhead < 2}


def main() -> int:
    if platform.system() != "Linux":
        print("benchmark requires a Linux host", file=sys.stderr)
        return 2
    cli = Path(os.environ.get("SENTRY_CLI", "target/release/sentry"))
    if not cli.is_file():
        print(f"missing Sentry CLI: {cli}; run cargo build --release -p sentry-cli", file=sys.stderr)
        return 2
    output = Path(os.environ.get("SENTRY_BENCHMARK_OUTPUT", "artifacts/overhead-baseline.json"))
    output.parent.mkdir(parents=True, exist_ok=True)
    prefix = [str(cli), "run", "--"]
    revision = os.environ.get("SENTRY_BUILD_REVISION", "unknown")
    evidence = {"schema_version": 1, "release_gate_open": True,
                "supported_modes": ["command_wrapper"],
                "unsupported_modes": ["observe", "dry_run", "enforce", "audit"],
                "gate_reason": "live observation, enforcement, and audit are not wired into the CLI",
                "metadata": {"kernel": platform.release(), "machine": platform.machine(),
                             "python": platform.python_version(), "repetitions": REPETITIONS,
                             "warmups": WARMUPS, "cpu_gate_percent": 2,
                             "build_revision": revision},
                "results": [measure("process-start", ["/bin/true"], prefix + ["/bin/true"]),
                            measure("50k-stat-syscalls", SYSCALL_WORKLOAD, prefix + SYSCALL_WORKLOAD)]}
    output.write_text(json.dumps(evidence, indent=2) + "\n", encoding="utf-8")
    print(output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
