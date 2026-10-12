"""S4: kill a run mid-task. The agent's next call fails and the log ends with run_halted."""

import threading
import time

import anyio
import httpx2
from mcp import Client
from mcp.client.streamable_http import streamable_http_client

from conftest import SCRIPTED, make_cfg

from stopcord import control
from stopcord.chain import read_entries, verify
from stopcord.gateway import run_agent


def test_kill_mid_run(isolated, monkeypatch):
    monkeypatch.setenv("STOPCORD_SCRIPTED_DELAY", "0.2")
    cfg = make_cfg(isolated)
    seen = {}

    def killer(gw):
        def go():
            # wait until the agent is a few calls in
            while gw.calls < 5:
                time.sleep(0.01)
            seen["url"] = gw.url
            seen["token"] = gw.token
            seen["reply"] = control.kill(gw.run_id, via="test")
            seen["killed_at"] = time.monotonic()
            # the agent's credential is dead: a fresh call with it must fail fast
            seen["after"] = anyio.run(_try_call, seen["url"], seen["token"])
            seen["after_elapsed"] = time.monotonic() - seen["killed_at"]

        threading.Thread(target=go, daemon=True).start()

    start = time.monotonic()
    out = anyio.run(lambda: run_agent(cfg, SCRIPTED + ["long"], on_ready=killer))
    assert out.halted
    assert out.exit_code == 3, "the scripted agent exits 3 when it loses its tools"
    assert time.monotonic() - start < 20
    assert seen["reply"]["ok"]
    assert seen["after"] == "rejected"
    assert seen["after_elapsed"] < 2.0

    entries = read_entries(out.log_path)
    assert entries[-1]["event"] == "run_halted"
    assert entries[-1]["detail"]["via"] == "test"
    assert entries[-1]["detail"]["upstream_terminated"] is True
    assert verify(out.log_path).ok
    # nothing ran after the halt, and fewer calls ran than the script wanted
    assert sum(1 for e in entries if e["event"] == "policy_decision") < 49


def test_kill_with_no_active_run_errors(isolated):
    assert control.find_run(None) is None


async def _try_call(url, token):
    try:
        async with httpx2.AsyncClient(headers={"Authorization": f"Bearer {token}"}, timeout=5) as http:
            async with Client(streamable_http_client(url, http_client=http), cache=None) as c:
                r = await c.call_tool("list_dir", {"path": "."})
                return "rejected" if r.is_error else "allowed"
    except Exception:
        return "rejected"
