"""`stopcord gateway` over stdio: what an MCP client config points at."""

import os
import sys

import anyio
from mcp import Client, StdioServerParameters

from conftest import QUICKSTART, make_cfg

from stopcord import control
from stopcord.chain import read_entries, verify


def test_stdio_gateway_decides_logs_and_halts(isolated):
    cfg = make_cfg(isolated)
    runs = isolated / "stdio-runs"

    async def go():
        params = StdioServerParameters(
            command=sys.executable,
            args=["-m", "stopcord.cli", "gateway", "--policy", str(QUICKSTART / "policy.yaml"), "--workspace", str(cfg.workspace), "--runs-dir", str(runs)],
            env={"STOPCORD_STATE_DIR": os.environ["STOPCORD_STATE_DIR"], "HOME": str(isolated)},
        )
        async with Client(params, cache=None) as c:
            names = {t.name for t in (await c.list_tools()).tools}
            ok = await c.call_tool("read_file", {"path": "README.md"})
            denied = await c.call_tool("read_file", {"path": ".env"})
            info = control.find_run(None)
            reply = control.kill(info["run_id"], via="test")
            after = await c.call_tool("list_dir", {"path": "."})
            return names, ok, denied, reply, after

    names, ok, denied, reply, after = anyio.run(go)
    assert {"read_file", "write_file", "run_command", "http_request"} <= names
    assert not ok.is_error and "# shop" in ok.content[0].text
    assert denied.is_error and denied.content[0].text == "Denied by policy (rule env-files)."
    assert reply["ok"]
    assert after.is_error and "halted" in after.content[0].text.lower()

    (log,) = runs.glob("*.jsonl")
    entries = read_entries(log)
    assert verify(log).ok
    assert entries[-1]["event"] == "run_halted"
    assert [e["rule_id"] for e in entries if e["event"] == "policy_decision"] == ["workspace-files", "env-files"]
