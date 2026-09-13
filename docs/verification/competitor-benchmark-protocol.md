# Competitor benchmark protocol

Status: record contract; no comparison result has been measured.

The benchmark compares evidence coverage on each tool's supported deployment.
It does not score a Kubernetes-only, CI-only, or hardware-attested product as
deficient when the selected self-hosted Linux environment is outside that
product's support boundary.

Each run must use the strict record shape checked by
`tests/benchmark/verify_benchmark_record.py`. It records the kernel,
architecture, enforcement mode, every compared tool's version and supported
environment, the fixed scenario corpus, and a conclusion. The corpus includes
normal workflow cases, adversarial lifecycle and DNS cases, and the four common
agent egress paths individually.

For each measured tool, attach the commands, raw output, and a record of
whether each path had any evidence and whether a third party could verify it.
Do not upgrade the conclusion from `not_demonstrated` until those artifacts
show a customer-valued advantage in a compatible environment. The checked-in
example is intentionally `not_run`: Sentry still lacks a live CLI-to-kernel
enforcement and event-ingestion path.
