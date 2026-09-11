#!/usr/bin/env bash
# Runs the two privileged arm64 kernel integration checks.
set -euo pipefail

if [ "$(docker info --format '{{.Architecture}}')" != "aarch64" ]; then
  echo "This runtime check requires a real Linux arm64 Docker host." >&2
  exit 2
fi

bash tests/vm/toolchain-spike/run-arm64-container-probe.sh
bash tests/vm/kernel-capabilities/probe-arm64-container.sh
