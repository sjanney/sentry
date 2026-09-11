#!/usr/bin/env bash
# Compatibility entry point for existing arm64 instructions.
exec bash "$(dirname "$0")/probe-linux-container.sh"
