# Overhead baseline protocol

The <2% CPU gate is defined before enforcement optimization: for each workload,
the mean child CPU time of `sentry run -- <workload>` must be less than 2% above
the direct workload mean. A zero-CPU baseline produces no gate result instead
of a misleading percentage.

Run `cargo build --release -p sentry-cli` and then
`python3 scripts/benchmark_overhead.py` on a supported Linux host. The runner
uses five warmups and 20 repeats for process-start and 50,000 `stat` syscalls.
It writes raw per-repeat CPU and wall-clock samples, mean, standard deviation,
p95, gate result, kernel/machine/Python metadata, and schema version to
`artifacts/overhead-baseline.json` (or `SENTRY_BENCHMARK_OUTPUT`).

This repository is currently being developed from macOS, where the sensor CLI
intentionally reports an unsupported host. No Linux baseline result is checked
in yet; the generated artifact is the evidence required before this ticket can
leave Backlog.

The runner currently measures only the Linux command wrapper. Its JSON marks
observe, dry-run, enforce, and audit as unsupported and keeps the release gate
open. Do not use its CPU figure to claim the <2% enforcement target until the
live modes are wired and measured under the declared matrix.

## Initial Linux container evidence

[`artifacts/overhead-baseline-linux-docker.json`](../../artifacts/overhead-baseline-linux-docker.json)
records the first reproducible Linux run on 2026-09-12: Docker Desktop's
Linux 6.12.54 VM on `aarch64`, Python 3.11.2, five warmups, and 20 repeats.
The 50,000-`stat` wrapper workload measured 0.95% mean child-CPU overhead;
the process-start workload measured 361.45%, where wrapper startup dominates
the very short baseline. These numbers are raw command-wrapper evidence only;
they do not pass or fail the enforcement release gate, which remains open.
