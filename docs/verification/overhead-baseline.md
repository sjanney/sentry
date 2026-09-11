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
