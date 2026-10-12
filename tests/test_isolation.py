"""The agent's tools can't reach the log directory, the policy file or gateway state."""

import anyio
import pytest

from conftest import make_cfg

from stopcord.gateway import Gateway


async def _calls(cfg, calls):
    gw = Gateway(cfg)
    out = []
    async with anyio.create_task_group() as tg:
        await gw.start(tg)
        for tool, args in calls:
            r = await gw.call_tool(tool, args)
            out.append((r.is_error, r.content[0].text))
        await gw.finish(0)
        await gw.shutdown()
        tg.cancel_scope.cancel()
    return out


def test_tools_cannot_read_log_policy_or_state(isolated):
    cfg = make_cfg(isolated)
    cfg.runs_dir.mkdir(parents=True, exist_ok=True)
    targets = [
        str(cfg.log_path),
        str(cfg.runs_dir),
        str(cfg.policy_path),
        str(cfg.state_dir / "deploy-credential.txt"),
        "../gateway/deploy-credential.txt",
        "../../../runs",
    ]
    calls = [("read_file", {"path": t}) for t in targets] + [("list_dir", {"path": str(cfg.runs_dir)})]
    calls.append(("write_file", {"path": str(cfg.log_path), "content": "{}"}))
    results = anyio.run(_calls, cfg, calls)
    for (tool, args), (is_error, text) in zip(calls, results):
        assert is_error and text.startswith("Denied by policy"), (tool, args, text)


def test_protected_beats_a_permissive_policy(isolated):
    """Even a policy that allows everything can't expose the log, if the log sits inside the workspace."""
    from conftest import QUICKSTART

    permissive = isolated / "allow-all.yaml"
    permissive.write_text("rules:\n  - {id: everything, effect: allow}\n")
    cfg = make_cfg(isolated)
    cfg.policy_path = permissive
    cfg.runs_dir = cfg.workspace / "runs"  # a careless setup: logs inside the workspace
    results = anyio.run(_calls, cfg, [("read_file", {"path": f"runs/{cfg.run_id}.jsonl"}), ("read_file", {"path": "allow-all.yaml"}), ("read_file", {"path": "README.md"})])
    assert results[0] == (True, "Denied by policy (rule gateway-protected).")
    assert results[1][0]  # outside workspace, and the policy file is protected anyway
    assert results[2][0] is False


def test_upstream_refuses_escape_even_if_gateway_did_not(isolated):
    """Defense in depth: the tools server checks containment on its own."""
    import os
    import sys

    from mcp import Client, StdioServerParameters

    cfg = make_cfg(isolated)

    async def go():
        params = StdioServerParameters(
            command=sys.executable,
            args=["-m", "stopcord.tools.server"],
            env={"STOPCORD_WORKSPACE": str(cfg.workspace), "STOPCORD_DEPLOY_CREDENTIAL": "/nonexistent", "STOPCORD_DEPLOY_OUT": str(isolated / "d")},
        )
        async with Client(params, cache=None) as c:
            return await c.call_tool("read_file", {"path": "../../../../etc/hosts"})

    r = anyio.run(go)
    assert r.is_error and "outside the workspace" in r.content[0].text
