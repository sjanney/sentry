#!/usr/bin/env python3
"""Validate an evidence-backed, reproducible competitor benchmark record."""

import json
import sys
from pathlib import Path


SCENARIOS = {
    "normal_dependency_install", "private_repository_access", "build_and_test",
    "synthetic_credential_read", "direct_ip_exfiltration", "dns_rebinding_or_expiry",
    "parser_differential_hostname", "proxy_use", "inherited_socket", "fork_exec_race",
    "daemon_failure", "event_buffer_exhaustion", "policy_update_or_permission_request",
    "mcp_a2a_tool_call", "shelled_cli", "improvised_http", "agent_authored_script",
}
REQUIRED = {"schema_version", "benchmark_id", "recorded_at", "environment", "tools", "scenarios", "conclusion"}
ENVIRONMENT = {"kernel_version", "architecture", "enforcement_mode"}
TOOL = {"name", "version", "supported_environment", "status", "reason"}
TOOL.add("results")
PATHS = {"mcp_a2a_tool_call", "shelled_cli", "improvised_http", "agent_authored_script"}


def fail(message: str) -> None:
    raise ValueError(message)


def main() -> None:
    if len(sys.argv) != 2:
        raise SystemExit("usage: verify_benchmark_record.py RECORD.json")
    record = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
    if set(record) != REQUIRED or record["schema_version"] != 1:
        fail("record must use exactly the benchmark schema v1 fields")
    if not all(isinstance(record[name], str) and record[name] for name in ("benchmark_id", "recorded_at")):
        fail("benchmark_id and recorded_at must be non-empty strings")
    if set(record["environment"]) != ENVIRONMENT or not all(
        isinstance(value, str) and value for value in record["environment"].values()
    ):
        fail("environment must record kernel_version, architecture, and enforcement_mode")
    if len(record["scenarios"]) != len(SCENARIOS) or set(record["scenarios"]) != SCENARIOS:
        fail("scenarios must cover the fixed comparison and four-path corpus")
    if not isinstance(record["tools"], list) or not record["tools"]:
        fail("tools must be a non-empty list")
    names = set()
    for tool in record["tools"]:
        if set(tool) != TOOL or not all(
            isinstance(tool[field], str) and tool[field]
            for field in TOOL - {"results"}
        ):
            fail("each tool must contain complete non-empty metadata")
        if tool["status"] not in {"not_run", "measured", "unsupported"}:
            fail("tool status must be not_run, measured, or unsupported")
        if tool["status"] == "measured":
            results = tool["results"]
            if not isinstance(results, dict) or set(results) != {"commands", "raw_result", "path_coverage"}:
                fail("a measured tool must provide commands, raw_result, and path_coverage")
            if not isinstance(results["commands"], list) or not results["commands"] or not all(
                isinstance(command, str) and command for command in results["commands"]
            ):
                fail("measured commands must be a non-empty string list")
            if not isinstance(results["raw_result"], str) or not results["raw_result"]:
                fail("a measured tool must reference non-empty raw results")
            if set(results["path_coverage"]) != PATHS or any(
                value not in {"none", "recorded", "third_party_verifiable"}
                for value in results["path_coverage"].values()
            ):
                fail("measured path coverage must classify all four paths")
        elif tool["results"] is not None:
            fail("not_run and unsupported tools must not include measured results")
        if tool["name"] in names:
            fail("tool names must be unique")
        names.add(tool["name"])
    if record["conclusion"] not in {"not_demonstrated", "advantage_demonstrated"}:
        fail("conclusion must state whether a measurable advantage exists")
    if record["conclusion"] == "advantage_demonstrated" and not any(
        tool["status"] == "measured" for tool in record["tools"]
    ):
        fail("an advantage requires at least one measured tool")
    print(f"verified benchmark record for {len(record['tools'])} tools and {len(SCENARIOS)} scenarios")


if __name__ == "__main__":
    main()
