"""The console's API: built from the log alone, follows runs, and stops them only with its page token."""

import anyio
from starlette.testclient import TestClient

from conftest import SCRIPTED, make_cfg

from stopcord.console import create_app
from stopcord.gateway import run_agent


def test_console_shows_a_finished_run(isolated):
    cfg = make_cfg(isolated, task="Fix the failing test")
    out = anyio.run(lambda: run_agent(cfg, SCRIPTED + ["fix"]))
    client = TestClient(create_app(cfg.runs_dir))
    latest = client.get("/api/latest").json()
    assert latest == {"run_id": out.run_id, "active": False}
    s = client.get(f"/api/runs/{out.run_id}").json()
    assert s["status"] == "finished" and s["task"] == "Fix the failing test"
    assert s["counts"] == {"total": 11, "allowed": 9, "blocked": 2}
    assert s["chain"]["ok"]
    assert [x["target"] for x in s["left_out"] if not x["mentioned"]] == [".env", "attacker.example"]
    assert "__CONSOLE_TOKEN__" not in client.get("/").text


def test_console_flags_an_edited_log(isolated):
    cfg = make_cfg(isolated)
    out = anyio.run(lambda: run_agent(cfg, SCRIPTED + ["fix"]))
    copy = cfg.runs_dir / f"{out.run_id}.tampered.jsonl"
    lines = out.log_path.read_text().splitlines(keepends=True)
    n = next(i for i, l in enumerate(lines, 1) if '"decision":"deny"' in l)
    lines[n - 1] = lines[n - 1].replace('"decision":"deny"', '"decision":"allow"')
    copy.write_text("".join(lines))
    s = TestClient(create_app(cfg.runs_dir)).get(f"/api/runs/{out.run_id}.tampered").json()
    assert s["tampered_copy"] and not s["chain"]["ok"] and s["chain"]["broken"] == n
    assert s["left_out"] == []  # no comparison against a broken log


def test_stop_needs_the_page_token(isolated):
    client = TestClient(create_app(isolated / "runs"))
    assert client.post("/api/runs/r1/stop").status_code == 403
    assert client.post("/api/runs/r1/stop", headers={"x-console-token": "nope"}).status_code == 403


def test_run_ids_cannot_escape_the_runs_dir(isolated):
    client = TestClient(create_app(isolated / "runs"))
    assert client.get("/api/runs/..%2F..%2Fetc%2Fpasswd").status_code == 404
