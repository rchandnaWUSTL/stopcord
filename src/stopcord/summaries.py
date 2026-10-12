"""Fixed English templates for the log's summary field. No model writes these."""

from __future__ import annotations


def fmt_target(tool: str, target: str | None) -> str:
    if target is None:
        return tool
    if tool in ("read_file", "write_file", "list_dir") and not target.startswith("/"):
        return f"{tool} ./workspace/{target}" if target != "." else f"{tool} ./workspace"
    return f"{tool} {target}"


def run_started(agent: str, policy_name: str, n_rules: int, budget: int) -> str:
    return f"Run started: agent {agent} under policy {policy_name} ({n_rules} rules, budget {budget} calls)"


def tool_requested(tool: str, target: str | None) -> str:
    return f"Requested: {fmt_target(tool, target)}"


def policy_decision(tool: str, target: str | None, allowed: bool, rule_id: str) -> str:
    verb = "Allowed" if allowed else "Denied"
    return f"{verb}: {fmt_target(tool, target)} (rule {rule_id})"


def tool_result(tool: str, target: str | None, ok: bool, nbytes: int) -> str:
    status = f"ok, {nbytes} bytes" if ok else f"error, {nbytes} bytes"
    return f"Result: {fmt_target(tool, target)} ({status})"


def run_halted(who: str, via: str) -> str:
    return f"Halted by {who} via {via}. Session token revoked."


def run_finished(calls: int, allowed: int, denied: int, exit_code: int | None) -> str:
    return f"Run finished: {calls} calls, {allowed} allowed, {denied} denied (agent exit code {exit_code})"
