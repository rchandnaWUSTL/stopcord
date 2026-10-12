"""A local web console for runs: live decisions, log integrity, the agent's report, and a stop button.

    stopcord console            # opens http://127.0.0.1:8765, follows the newest run

Everything shown is computed from the log and the agent's summary file, the
same way `stopcord report` does it. No model is involved. The stop button
sends the same kill message as `stopcord kill`.
"""

from __future__ import annotations

import json
import secrets
from importlib.resources import files
from pathlib import Path
from typing import Any

from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import HTMLResponse, JSONResponse
from starlette.routing import Route

from stopcord import control
from stopcord.chain import verify
from stopcord.report import analyze

FS_TOOLS = ("read_file", "write_file", "list_dir")


def _entries(log: Path) -> list[dict[str, Any]]:
    """Parse what can be parsed. A tampered line stops the list; verify says where."""
    out = []
    for line in log.read_bytes().splitlines():
        if not line.strip():
            continue
        try:
            out.append(json.loads(line))
        except ValueError:
            break
    return out


def _display(e: dict[str, Any]) -> str:
    args = e.get("args") or {}
    if e.get("tool") == "http_request":
        return f"{str(args.get('method') or 'GET').upper()} {args.get('url')}"
    return e.get("target") or ""


def run_state(log: Path) -> dict[str, Any]:
    entries = _entries(log)
    chain = verify(log)
    start = entries[0] if entries else {}
    detail = start.get("detail") or {}
    run_id = log.name.removesuffix(".jsonl")
    active = {i["run_id"] for i in control.active_runs()}
    last = entries[-1] if entries else {}

    calls = []
    results: dict[tuple[str, str], dict[str, Any]] = {}
    for e in entries:
        if e.get("event") == "policy_decision":
            calls.append({
                "seq": e["seq"], "ts": e["ts"], "tool": e.get("tool"), "target": _display(e),
                "decision": e.get("decision"), "rule": e.get("rule_id"), "result": None,
            })
        elif e.get("event") == "tool_result" and calls:
            for c in reversed(calls):
                if c["tool"] == e.get("tool") and c["result"] is None and c["decision"] == "allow":
                    c["result"] = "error" if (e.get("detail") or {}).get("is_error") else "ok"
                    break

    status = "running" if run_id in active else ("halted" if last.get("event") == "run_halted" else "finished" if last.get("event") == "run_finished" else "incomplete")
    summary_path = log.with_name(run_id.split(".")[0] + ".summary.txt")
    summary = summary_path.read_text() if summary_path.exists() and status != "running" else None
    left_out: list[dict[str, Any]] = []
    if summary is not None and chain.ok:
        a = analyze(log, summary)
        left_out = [{"seq": i.seq, "tool": i.tool, "target": i.target, "rule": i.rule_id, "mentioned": i.mentioned} for i in a.denied_items]

    halted = None
    if last.get("event") == "run_halted":
        d = last.get("detail") or {}
        halted = {"who": d.get("who"), "via": d.get("via"), "ts": last.get("ts"), "seq": last.get("seq")}

    return {
        "run_id": run_id,
        "tampered_copy": ".tampered" in run_id,
        "task": detail.get("task"),
        "agent": detail.get("agent"),
        "policy": detail.get("policy_name"),
        "rules": None,
        "status": status,
        "calls": calls,
        "counts": {
            "total": len(calls),
            "allowed": sum(1 for c in calls if c["decision"] == "allow"),
            "blocked": sum(1 for c in calls if c["decision"] == "deny"),
        },
        "chain": {"ok": chain.ok, "entries": chain.entries, "broken": chain.broken_seq, "reason": chain.reason, "head": chain.head},
        "summary": summary,
        "left_out": left_out,
        "halted": halted,
    }


def create_app(runs_dir: Path) -> Starlette:
    runs_dir = Path(runs_dir)
    page_token = secrets.token_urlsafe(16)
    html = (files("stopcord") / "web" / "console.html").read_text().replace("__CONSOLE_TOKEN__", page_token)

    def find(run_id: str) -> Path | None:
        if "/" in run_id or ".." in run_id:
            return None
        p = runs_dir / f"{run_id}.jsonl"
        if p.exists():
            return p
        info = control.find_run(run_id)
        return Path(info["log"]) if info else None

    async def index(request: Request):
        return HTMLResponse(html)

    async def latest(request: Request):
        runs = control.active_runs()
        if runs:
            return JSONResponse({"run_id": runs[0]["run_id"], "active": True})
        logs = sorted((p for p in runs_dir.glob("r*.jsonl") if ".tampered" not in p.name), key=lambda p: p.stat().st_mtime)
        return JSONResponse({"run_id": logs[-1].name.removesuffix(".jsonl") if logs else None, "active": False})

    async def run(request: Request):
        p = find(request.path_params["run_id"])
        if p is None:
            return JSONResponse({"error": "no such run"}, status_code=404)
        return JSONResponse(run_state(p))

    async def stop(request: Request):
        if request.headers.get("x-console-token") != page_token:
            return JSONResponse({"error": "forbidden"}, status_code=403)
        run_id = request.path_params["run_id"]
        if control.find_run(run_id) is None:
            return JSONResponse({"ok": False, "error": "run is not active"}, status_code=409)
        return JSONResponse(control.kill(run_id, via="console"))

    return Starlette(routes=[
        Route("/", index),
        Route("/api/latest", latest),
        Route("/api/runs/{run_id}", run),
        Route("/api/runs/{run_id}/stop", stop, methods=["POST"]),
    ])
