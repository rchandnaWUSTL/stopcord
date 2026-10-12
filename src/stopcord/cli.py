"""stopcord: run | gateway | console | demo | tail | kill | verify | replay | report"""

from __future__ import annotations

import json
import os
import sys
import threading
import time
from importlib.resources import files
from pathlib import Path
from typing import Annotated, Optional

import anyio
import typer
from rich.console import Console
from rich.text import Text

from stopcord import __version__, control
from stopcord.chain import TERMINAL_EVENTS, verify as verify_chain

app = typer.Typer(add_completion=False, no_args_is_help=True, help="A containment layer for AI agents. Gate, log, kill switch, replay.")
console = Console(highlight=False)
err = Console(stderr=True, highlight=False)

QUICKSTART = Path(str(files("stopcord") / "quickstart"))
DEFAULT_RUNS = Path("runs")


def _short(h: str | None, n: int = 12) -> str:
    return (h or "")[:n]


def _print_verify(log: Path, policy_sha: str | None = None) -> bool:
    r = verify_chain(log, policy_sha)
    if r.ok:
        console.print(Text.assemble(("verify  ", "bold"), ("OK", "bold green"), f"  {r.entries} entries, head {_short(r.head)}"))
    else:
        console.print(Text.assemble(("verify  ", "bold"), ("FAILED", "bold white on red"), f" at entry {r.broken_seq}: {r.reason}"))
    return r.ok


def _resolve_log(run_or_log: str | None, runs_dir: Path) -> Path:
    if run_or_log and Path(run_or_log).exists():
        return Path(run_or_log)
    if run_or_log:
        p = runs_dir / f"{run_or_log}.jsonl"
        if p.exists():
            return p
        info = control.find_run(run_or_log)
        if info:
            return Path(info["log"])
        raise typer.BadParameter(f"no log or run named {run_or_log}")
    logs = sorted(runs_dir.glob("r*.jsonl"), key=lambda p: p.stat().st_mtime)
    if not logs:
        raise typer.BadParameter(f"no logs in {runs_dir}")
    return logs[-1]


@app.command()
def run(
    agent: Annotated[list[str], typer.Argument(help="The agent command, after --")],
    policy: Annotated[Path, typer.Option(help="policy.yaml")] = QUICKSTART / "policy.yaml",
    workspace: Annotated[Path, typer.Option(help="Workspace the tools act on")] = QUICKSTART / "workspace",
    copy: Annotated[bool, typer.Option(help="Run on a fresh copy of the workspace (default) or in place")] = True,
    runs_dir: Annotated[Path, typer.Option(help="Where logs go")] = DEFAULT_RUNS,
    label: Annotated[str, typer.Option(help="Agent label recorded in the log", envvar="STOPCORD_LABEL")] = "",
    env_file: Annotated[Optional[Path], typer.Option(help="KEY=value file passed to the agent only (e.g. a model API key)")] = None,
    task: Annotated[Optional[str], typer.Option(help="The task you gave the agent. Recorded in the log and passed as STOPCORD_TASK", envvar="STOPCORD_TASK")] = None,
):
    """Run an agent behind the gateway. Its only way to act is the gateway's MCP endpoint."""
    from stopcord.gateway import RunConfig, prepare_workspace, run_agent

    cfg = RunConfig(policy_path=policy, workspace=workspace, runs_dir=runs_dir, agent_label=label or Path(agent[0]).name, task=task)
    if copy:
        cfg.workspace = prepare_workspace(workspace, cfg)
    extra = _read_env_file(env_file) if env_file else None
    out = anyio.run(lambda: run_agent(cfg, agent, extra_env=extra))
    _print_outcome(out)
    if out.summary_path:
        _write_report(out.log_path, out.summary_path, open_it=False)
    raise typer.Exit(0 if out.exit_code == 0 or out.halted else 1)


def _read_env_file(path: Path) -> dict[str, str]:
    env = {}
    for line in path.read_text().splitlines():
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            k, v = line.split("=", 1)
            env[k.strip().removeprefix("export ").strip()] = v.strip().strip('"').strip("'")
    return env


def _print_outcome(out) -> None:
    console.print()
    console.rule("[bold]stopcord")
    console.print(f"[bold]run[/]     {out.run_id}")
    status = "[bold red]halted[/]" if out.halted else f"finished (agent exit {out.exit_code})"
    console.print(f"[bold]status[/]  {status}")
    console.print(f"[bold]calls[/]   {out.calls}  ([green]{out.allowed} allowed[/], [red]{out.denied} denied[/])")
    console.print(f"[bold]log[/]     {_rel(out.log_path)}")
    _print_verify(out.log_path)


def _rel(p: Path) -> str:
    try:
        return str(Path(p).resolve().relative_to(Path.cwd()))
    except ValueError:
        return str(p)


@app.command()
def gateway(
    policy: Annotated[Path, typer.Option(help="policy.yaml")],
    workspace: Annotated[Path, typer.Option(help="Workspace the tools act on (used in place)")],
    runs_dir: Annotated[Path, typer.Option(help="Where logs go")] = Path.home() / ".stopcord" / "runs",
    label: Annotated[str, typer.Option(help="Agent label recorded in the log")] = "mcp-client",
):
    """Serve the gateway over stdio. Point your MCP client config here."""
    from stopcord.gateway import RunConfig, serve_stdio

    cfg = RunConfig(
        policy_path=policy,
        workspace=workspace,
        runs_dir=runs_dir,
        agent_label=label,
        work_root=Path.home() / ".stopcord" / "work",
    )
    anyio.run(serve_stdio, cfg)


@app.command()
def demo(
    scenario: Annotated[str, typer.Option(help="fix (S1-S3) or long (S4)")] = "fix",
    fast: Annotated[bool, typer.Option(help="No pauses between calls")] = False,
    runs_dir: Annotated[Path, typer.Option(help="Where logs go")] = DEFAULT_RUNS,
    open_report: Annotated[bool, typer.Option("--open/--no-open", help="Open the report in a browser")] = True,
):
    """Run the scripted agent on the quickstart fixture. No API key, no network."""
    from stopcord.gateway import RunConfig, prepare_workspace, run_agent

    if fast:
        os.environ["STOPCORD_SCRIPTED_DELAY"] = "0"
    cfg = RunConfig(policy_path=QUICKSTART / "policy.yaml", workspace=QUICKSTART / "workspace", runs_dir=runs_dir, agent_label="scripted agent (test fixture)", task="Fix the failing test" if scenario == "fix" else "Refactor every module")
    cfg.workspace = prepare_workspace(QUICKSTART / "workspace", cfg)
    out = anyio.run(run_agent, cfg, [sys.executable, "-m", "stopcord.agents.scripted", scenario])
    _print_outcome(out)
    if out.summary_path:
        _write_report(out.log_path, out.summary_path, open_report)
    console.print(f"\nChange one byte in that log, then run [bold]stopcord verify {_rel(out.log_path)}[/]")
    raise typer.Exit(0 if out.exit_code == 0 or out.halted else 1)


def _write_report(log: Path, summary: Path, open_it: bool) -> Path:
    from stopcord.report import write_report

    html = log.with_suffix(".report.html")
    write_report(log, summary.read_text(), html)
    console.print(f"[bold]report[/]  {_rel(html)}")
    if open_it and sys.stdout.isatty():
        import webbrowser

        webbrowser.open(html.resolve().as_uri())
    return html


@app.command()
def verify(
    log: Annotated[Path, typer.Argument(help="A run's .jsonl log")],
    policy: Annotated[Optional[Path], typer.Option(help="Also check the log was written under this policy file")] = None,
):
    """Recompute the hash chain. Prints OK and the head hash, or the first broken entry."""
    import hashlib

    sha = hashlib.sha256(policy.read_bytes()).hexdigest() if policy else None
    r = verify_chain(log, sha)
    if r.ok:
        console.print(Text.assemble(("OK", "bold green"), f"  {r.entries} entries"))
        console.print(f"head {r.head}")
        for w in r.warnings[:-1]:
            console.print(f"[yellow]warning:[/] {w}")
        raise typer.Exit(0)
    console.print(Text.assemble(("FAILED", "bold white on red"), f"  at entry {r.broken_seq}"))
    console.print(f"{r.reason}")
    raise typer.Exit(1)


@app.command()
def kill(run_id: Annotated[Optional[str], typer.Argument(help="Run to halt (default: newest active run)")] = None):
    """Halt a run mid-task and revoke the agent's session token."""
    info = control.find_run(run_id)
    if not info:
        err.print("no active run found")
        raise typer.Exit(1)
    reply = control.kill(info["run_id"], via="cli")
    if not reply.get("ok"):
        err.print(f"kill failed: {reply.get('error')}")
        raise typer.Exit(1)
    console.print(f"[bold red]halted[/] {info['run_id']} at entry {reply['seq']}. Session token revoked.")


# -- tail ----------------------------------------------------------------------

STYLE = {"allow": ("ALLOW", "green"), "deny": ("DENIED", "bold red")}


def _tail_line(e: dict, all_events: bool) -> Text | None:
    ev = e.get("event")
    seq = f"{e.get('seq', 0):>3} "
    if ev == "policy_decision":
        word, style = STYLE.get(e.get("decision"), ("?", "white"))
        target = e.get("target") or ""
        t = Text.assemble((seq, "dim"), (f"{word:<7}", style), (f"{e.get('tool')} ", "bold" if word == "DENIED" else ""), (target, style if word == "DENIED" else ""))
        if word == "DENIED":
            t.append(f"  rule {e.get('rule_id')}", "red")
        return t
    if ev == "run_started":
        d = e.get("detail") or {}
        return Text.assemble((seq, "dim"), ("START  ", "bold cyan"), f"{d.get('agent')} · policy {d.get('policy_name')}")
    if ev == "run_halted":
        d = e.get("detail") or {}
        return Text.assemble((seq, "dim"), ("HALTED ", "bold white on red"), f" by {d.get('who')} via {d.get('via')} · token revoked")
    if ev == "run_finished":
        d = e.get("detail") or {}
        return Text.assemble((seq, "dim"), ("END    ", "bold cyan"), f"{d.get('calls')} calls · {d.get('denied')} denied")
    if all_events:
        return Text.assemble((seq, "dim"), (f"{ev} ", "dim"), e.get("summary") or "")
    return None


def _key_listener(get_run_id, stop: threading.Event) -> None:
    """K kills the run being tailed, q quits. Needs a real terminal."""
    if not sys.stdin.isatty():
        return
    import termios
    import tty

    fd = sys.stdin.fileno()
    old = termios.tcgetattr(fd)
    try:
        tty.setcbreak(fd)
        import select

        while not stop.is_set():
            r, _, _ = select.select([sys.stdin], [], [], 0.1)
            if not r:
                continue
            ch = sys.stdin.read(1)
            if ch in ("k", "K"):
                rid = get_run_id()
                if rid:
                    try:
                        control.kill(rid, via="tail")
                    except OSError as e:
                        console.print(f"[red]kill failed: {e}[/]")
            elif ch in ("q", "Q"):
                stop.set()
    finally:
        termios.tcsetattr(fd, termios.TCSADRAIN, old)


@app.command()
def tail(
    run_or_log: Annotated[Optional[str], typer.Argument(help="Run id or log path (default: wait for the next run)")] = None,
    runs_dir: Annotated[Path, typer.Option(help="Where logs go")] = DEFAULT_RUNS,
    all_events: Annotated[bool, typer.Option("--all", help="Show every event, not just decisions")] = False,
    exit_at_end: Annotated[bool, typer.Option("--exit", help="Exit when the run ends")] = False,
):
    """Live view of a run's log. Press K to kill the run, q to quit."""
    stop = threading.Event()
    state: dict = {"run_id": None}
    threading.Thread(target=_key_listener, args=(lambda: state["run_id"], stop), daemon=True).start()

    if run_or_log:
        log = _resolve_log(run_or_log, runs_dir)
    else:
        console.print("[dim]waiting for a run…  (K kills it, q quits)[/]")
        started = time.time()
        log = None
        while not stop.is_set() and log is None:
            for info in control.active_runs():
                if info["started"] >= started - 1:
                    log = Path(info["log"])
            time.sleep(0.05)
        if log is None:
            return
    state["run_id"] = log.stem
    console.print(Text.assemble(("log ", "dim"), (log.stem, "bold")))
    pos = 0
    buf = b""
    while not stop.is_set():
        if log.exists():
            with open(log, "rb") as fh:
                fh.seek(pos)
                chunk = fh.read()
                pos += len(chunk)
            buf += chunk
            *lines, buf = buf.split(b"\n")
            for line in lines:
                if not line.strip():
                    continue
                e = json.loads(line)
                t = _tail_line(e, all_events)
                if t is not None:
                    console.print(t, no_wrap=True, overflow="ellipsis")
                if e.get("event") in TERMINAL_EVENTS:
                    state["run_id"] = None
                    if exit_at_end:
                        stop.set()
        time.sleep(0.05)


@app.command()
def replay(log: Annotated[Path, typer.Argument(help="A run's .jsonl log")]):
    """Rebuild the timeline from the log alone. Verification status comes first."""
    from stopcord.report import print_replay

    raise typer.Exit(print_replay(log, console))


@app.command()
def report(
    log: Annotated[Path, typer.Argument(help="A run's .jsonl log")],
    summary: Annotated[Path, typer.Option(help="The agent's own final summary, as text")],
    html: Annotated[Path, typer.Option(help="Where to write the report")] = Path("report.html"),
):
    """Write a self-contained HTML page: what the agent said next to what the log shows."""
    from stopcord.report import write_report

    write_report(log, summary.read_text(), html)
    console.print(f"wrote {html}")


@app.command("console")
def console_cmd(
    runs_dir: Annotated[Path, typer.Option(help="Where logs go")] = DEFAULT_RUNS,
    port: Annotated[int, typer.Option(help="Port on 127.0.0.1")] = 8765,
    open_browser: Annotated[bool, typer.Option("--open/--no-open", help="Open it in a browser")] = True,
):
    """Local web console: live decisions, log integrity, the agent's report, and a stop button."""
    import uvicorn

    from stopcord.console import create_app

    url = f"http://127.0.0.1:{port}"
    console.print(f"console on {url} (follows the newest run; add ?run=<id> to pin one)")
    if open_browser and sys.stdout.isatty():
        import webbrowser

        webbrowser.open(url)
    uvicorn.run(create_app(runs_dir), host="127.0.0.1", port=port, log_level="warning")


@app.command()
def version():
    """Print the version."""
    console.print(__version__)


if __name__ == "__main__":
    app()
