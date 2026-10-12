"""Replay and report. Built from the log and the agent's summary alone.

No model is used anywhere in this file. The "not mentioned" check is a plain,
case-insensitive substring match, and the page says so.
"""

from __future__ import annotations

import hashlib
import html
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path, PurePosixPath
from typing import Any

from rich.console import Console
from rich.text import Text

from stopcord.chain import VerifyResult, read_entries, verify


@dataclass
class Item:
    seq: int
    tool: str
    target: str
    rule_id: str | None
    tried: list[str]
    mentioned: bool


@dataclass
class Analysis:
    run_id: str
    agent: str
    policy_name: str
    policy_sha256: str
    started: str | None
    ended: str | None
    chain: VerifyResult
    calls: int = 0
    allowed: int = 0
    denied: int = 0
    denied_items: list[Item] = field(default_factory=list)
    files_written: list[Item] = field(default_factory=list)
    hosts_contacted: list[Item] = field(default_factory=list)
    commands: list[str] = field(default_factory=list)
    halted: dict[str, Any] | None = None
    exit_code: int | None = None
    summary_sha_recorded: str | None = None
    summary_sha_actual: str | None = None


def _candidates(e: dict[str, Any]) -> list[str]:
    """The strings a summary could use to name what this call touched."""
    out: list[str] = []
    target = e.get("target") or ""
    args = e.get("args") or {}
    if e.get("tool") == "http_request":
        out += [target, str(args.get("url") or "")]
    elif e.get("tool") in ("read_file", "write_file", "list_dir"):
        raw = args.get("path") if isinstance(args.get("path"), str) else ""
        name = PurePosixPath(target).name
        out += [raw, target, name if len(name) >= 3 else ""]
    else:
        out.append(target)
    seen: list[str] = []
    for c in out:
        c = c.strip()
        if c and c not in seen:
            seen.append(c)
    return seen


def _mentioned(candidates: list[str], summary: str) -> bool:
    low = summary.lower()
    return any(c.lower() in low for c in candidates)


def analyze(log: Path, summary: str) -> Analysis:
    chain = verify(log)
    entries = read_entries(log) if chain.ok or chain.broken_seq != 1 else []
    start = entries[0] if entries else {}
    detail = start.get("detail") or {}
    a = Analysis(
        run_id=start.get("run_id") or log.stem,
        agent=str(detail.get("agent") or "agent"),
        policy_name=str(detail.get("policy_name") or "?"),
        policy_sha256=str(detail.get("policy_sha256") or ""),
        started=start.get("ts"),
        ended=entries[-1].get("ts") if entries else None,
        chain=chain,
        summary_sha_actual=hashlib.sha256(summary.encode()).hexdigest(),
    )
    decisions: dict[int, dict[str, Any]] = {}
    for e in entries:
        ev = e.get("event")
        if ev == "policy_decision":
            a.calls += 1
            if e.get("decision") == "allow":
                a.allowed += 1
                decisions[a.calls] = e
            else:
                a.denied += 1
                c = _candidates(e)
                a.denied_items.append(Item(e["seq"], e["tool"], e.get("target") or "", e.get("rule_id"), c, _mentioned(c, summary)))
        elif ev == "tool_result":
            ok = not (e.get("detail") or {}).get("is_error")
            req = _matching_request(entries, e)
            if not ok or req is None:
                continue
            c = _candidates(req)
            item = Item(req["seq"], req["tool"], req.get("target") or "", req.get("rule_id"), c, _mentioned(c, summary))
            if e["tool"] == "write_file" and item.target not in [i.target for i in a.files_written]:
                a.files_written.append(item)
            elif e["tool"] == "http_request" and item.target not in [i.target for i in a.hosts_contacted]:
                a.hosts_contacted.append(item)
            elif e["tool"] == "run_command":
                a.commands.append(item.target)
        elif ev == "run_halted":
            a.halted = {**(e.get("detail") or {}), "seq": e["seq"], "ts": e["ts"]}
        elif ev == "run_finished":
            d = e.get("detail") or {}
            a.exit_code = d.get("exit_code")
            a.summary_sha_recorded = d.get("agent_summary_sha256")
    return a


def _matching_request(entries: list[dict[str, Any]], result: dict[str, Any]) -> dict[str, Any] | None:
    """The policy_decision entry a tool_result answers: the latest allowed one for the same tool and target."""
    for e in reversed(entries[: result["seq"] - 1]):
        if e.get("event") == "policy_decision" and e.get("tool") == result.get("tool") and e.get("target") == result.get("target"):
            return e
    return None


# ---------------------------------------------------------------------------
# replay


def print_replay(log: Path, console: Console) -> int:
    r = verify(log)
    if r.ok:
        console.print(Text.assemble(("chain  ", "bold"), ("OK", "bold green"), f"  {r.entries} entries, head {r.head}"))
    else:
        console.print(Text.assemble(("chain  ", "bold"), ("FAILED", "bold white on red"), f"  at entry {r.broken_seq}: {r.reason}"))
        console.print("[yellow]Showing entries anyway. Nothing from the broken entry on can be trusted.[/]")
    console.print()
    try:
        entries = read_entries(log)
    except ValueError:
        entries = []
        for line in log.read_bytes().splitlines():
            try:
                import json

                entries.append(json.loads(line))
            except ValueError:
                break
    t0 = None
    for e in entries:
        ts = _ts(e.get("ts"))
        t0 = t0 or ts
        rel = f"+{(ts - t0).total_seconds():6.2f}s" if ts and t0 else "        "
        ev = e.get("event", "?")
        style = "dim"
        if ev == "policy_decision":
            style = "green" if e.get("decision") == "allow" else "bold red"
        elif ev in ("run_halted",):
            style = "bold red"
        elif ev in ("run_started", "run_finished"):
            style = "bold cyan"
        if ev in ("tool_requested",):
            continue
        console.print(Text.assemble((f"{e.get('seq', '?'):>4} ", "dim"), (rel + "  ", "dim"), (e.get("summary") or ev, style)))
    return 0 if r.ok else 1


def _ts(s: str | None) -> datetime | None:
    if not s:
        return None
    try:
        return datetime.strptime(s, "%Y-%m-%dT%H:%M:%S.%fZ")
    except ValueError:
        return None


# ---------------------------------------------------------------------------
# HTML report

CSS = """
:root{--bg:#0b0d10;--panel:#14181d;--line:#262c34;--text:#eef1f4;--muted:#9aa4af;--faint:#6b7480;
--red:#ff5a5f;--red-bg:rgba(255,90,95,.10);--ok:#5ad19a;--mono:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;
--sans:-apple-system,BlinkMacSystemFont,"Segoe UI",Inter,Roboto,Helvetica,Arial,sans-serif}
*{box-sizing:border-box}
html{background:var(--bg)}
body{margin:0;background:var(--bg);color:var(--text);font:400 18px/1.5 var(--sans);-webkit-font-smoothing:antialiased}
main{max-width:1400px;margin:0 auto;padding:40px 48px 56px}
header{display:flex;flex-wrap:wrap;gap:12px 24px;align-items:baseline;justify-content:space-between;margin-bottom:28px}
.brand{font:600 15px/1 var(--mono);letter-spacing:.04em;color:var(--muted)}
.brand b{color:var(--text)}
.meta{font:14px/1.4 var(--mono);color:var(--faint)}
h1{font-size:clamp(28px,3.2vw,44px);line-height:1.15;font-weight:700;letter-spacing:-.02em;margin:0 0 32px;max-width:24ch}
.cols{display:grid;grid-template-columns:1fr 1fr;gap:28px}
.card{background:var(--panel);border:1px solid var(--line);border-radius:18px;padding:32px 34px}
.label{font:700 14px/1 var(--sans);letter-spacing:.14em;text-transform:uppercase;color:var(--muted);margin:0 0 22px}
.said{font-size:clamp(22px,2.1vw,30px);line-height:1.45;margin:0;white-space:pre-wrap;word-break:break-word}
.said.long{font-size:clamp(18px,1.5vw,22px)}
.said.xlong{font-size:clamp(16px,1.2vw,18px)}
.said::before{content:"\\201C";color:var(--faint)}
.said::after{content:"\\201D";color:var(--faint)}
.who{margin-top:24px;font:15px/1.4 var(--mono);color:var(--faint)}
.stats{display:flex;gap:28px;margin:0 0 26px;flex-wrap:wrap}
.stat b{display:block;font-size:44px;line-height:1;font-weight:700;letter-spacing:-.02em}
.stat span{font-size:15px;color:var(--muted)}
.stat.deny b{color:var(--red)}
.deny-row{display:grid;grid-template-columns:1fr auto;gap:6px 16px;align-items:center;border-left:4px solid var(--red);background:var(--red-bg);border-radius:10px;padding:14px 18px;margin:0 0 12px}
.deny-row .what{font:600 22px/1.3 var(--mono);color:var(--text);overflow-wrap:anywhere}
.deny-row .what em{font-style:normal;color:var(--red)}
.deny-row .why{grid-column:1;font:15px/1.3 var(--mono);color:var(--muted)}
.tag{grid-row:1 / span 2;grid-column:2;font:700 14px/1 var(--sans);letter-spacing:.08em;text-transform:uppercase;padding:9px 12px;border-radius:8px;white-space:nowrap}
.tag.nm{color:var(--red);border:2px solid var(--red)}
.tag.m{color:var(--muted);border:2px solid var(--line)}
.minor{border-left:4px solid var(--red);border-radius:10px;padding:12px 18px;margin:0 0 12px;background:rgba(255,90,95,.05)}
.minor p{margin:0 0 8px;font-size:15px;color:var(--muted)}
.minor ul{list-style:none;margin:0;padding:0;font:15px/1.5 var(--mono)}
.minor li{display:flex;justify-content:space-between;gap:16px;padding:3px 0}
.minor .mt{color:var(--text);overflow-wrap:anywhere}
.minor .mt em{font-style:normal;color:var(--red)}
.minor .mnm{color:var(--red);white-space:nowrap}
.minor .mm{color:var(--faint);white-space:nowrap}
.facts{margin:22px 0 0;display:grid;grid-template-columns:auto 1fr;gap:10px 18px;font-size:17px}
.facts dt{color:var(--muted)}
.facts dd{margin:0;font-family:var(--mono);overflow-wrap:anywhere}
.facts .small{color:var(--faint);font-family:var(--sans)}
.ok{color:var(--ok)}
.broken{background:var(--red);color:#fff;font-weight:700;padding:16px 22px;border-radius:12px;margin:0 0 24px;font-size:20px}
.note{margin:28px 0 0;color:var(--muted);font-size:16px;max-width:80ch}
details{margin-top:28px;border-top:1px solid var(--line);padding-top:18px}
summary{cursor:pointer;color:var(--muted);font-size:16px}
ol{list-style:none;padding:0;margin:14px 0 0;font:14px/1.7 var(--mono);color:var(--muted)}
ol li.d{color:var(--red)}
ol .s{color:var(--faint);display:inline-block;min-width:3.5ch}
@media (max-width:820px){
 main{padding:22px 16px 40px}
 .cols{grid-template-columns:1fr;gap:18px}
 .card{padding:22px 20px;border-radius:14px}
 body{font-size:16px}
 .stat b{font-size:36px}
 .deny-row{grid-template-columns:1fr}
 .tag{grid-row:auto;grid-column:1;justify-self:start}
 .deny-row .what{font-size:19px}
 .minor li{flex-direction:column;gap:0;padding:5px 0}
}
"""


def _e(s: Any) -> str:
    return html.escape(str(s), quote=True)


TARGET_CHARS = 48


def _target_html(item: Item) -> str:
    t = item.target
    shown = t if len(t) <= TARGET_CHARS else t[: TARGET_CHARS - 1] + "…"
    return f'{_e(item.tool)} <em title="{_e(t)}">{_e(shown)}</em>'


def _said_class(summary: str) -> str:
    n = len(summary.strip())
    return "said" if n <= 420 else ("said long" if n <= 900 else "said xlong")


def render_html(a: Analysis, summary: str, log_name: str, timeline: list[dict[str, Any]]) -> str:
    # Denials under a named policy rule get a full row. Calls that only fell
    # through to default-deny (usually commands off the allowlist) are listed
    # compactly underneath. Everything denied is shown either way.
    major = [i for i in a.denied_items if i.rule_id != "default-deny"]
    minor = [i for i in a.denied_items if i.rule_id == "default-deny"]
    deny_rows = []
    for it in major:
        tag = '<span class="tag nm">Not mentioned</span>' if not it.mentioned else '<span class="tag m">Mentioned</span>'
        deny_rows.append(
            f'<div class="deny-row"><div class="what">{_target_html(it)}</div>{tag}'
            f'<div class="why">denied · rule {_e(it.rule_id)} · entry {it.seq}</div></div>'
        )
    if minor:
        items = "".join(
            f'<li><span class="mt">{_target_html(it)}</span>'
            f'<span class="{"mnm" if not it.mentioned else "mm"}">{"not mentioned" if not it.mentioned else "mentioned"} · entry {it.seq}</span></li>'
            for it in minor
        )
        deny_rows.append(f'<div class="minor"><p>Also denied by default ({len(minor)})</p><ul>{items}</ul></div>')
    if not a.denied_items:
        deny_rows.append('<p class="facts small">No calls were denied.</p>')

    def listing(items: list[Item]) -> str:
        if not items:
            return '<span class="small">none</span>'
        parts = []
        for it in items:
            m = "mentioned" if it.mentioned else "not mentioned"
            parts.append(f'{_e(it.target)} <span class="small">({m})</span>')
        return "<br>".join(parts)

    if a.chain.ok:
        chain = f'<span class="ok">verified</span> <span class="small">· {a.chain.entries} entries · head {_e((a.chain.head or "")[:16])}…</span>'
        banner = ""
    else:
        chain = f'<b style="color:var(--red)">FAILED at entry {a.chain.broken_seq}</b> <span class="small">· {_e(a.chain.reason)}</span>'
        banner = f'<div class="broken">This log failed verification at entry {a.chain.broken_seq}. Nothing on the right can be trusted.</div>'

    if a.halted:
        halted = f'yes <span class="small">· by {_e(a.halted.get("who"))} via {_e(a.halted.get("via"))} · entry {a.halted.get("seq")}</span>'
    else:
        halted = '<span class="small">no</span>'

    if a.summary_sha_recorded is None:
        bound = "not recorded in the log"
    elif a.summary_sha_recorded == a.summary_sha_actual:
        bound = "matches the hash recorded when the run ended"
    else:
        bound = "does not match the hash recorded when the run ended"

    tl = []
    for e in timeline:
        if e.get("event") == "tool_requested":
            continue
        cls = ' class="d"' if e.get("decision") == "deny" or e.get("event") == "run_halted" else ""
        tl.append(f'<li{cls}><span class="s">{_e(e.get("seq"))}</span> {_e(e.get("summary") or e.get("event"))}</li>')

    when = (a.started or "")[:19].replace("T", " ")
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="color-scheme" content="dark">
<title>Run {_e(a.run_id)} · StopCord</title>
<style>{CSS}</style></head>
<body><main>
<header><div class="brand"><b>StopCord</b> · run report</div>
<div class="meta">{_e(a.run_id)} · {_e(when)} UTC · policy {_e(a.policy_name)}</div></header>
{banner}
<h1>The summary is a claim. The log is the evidence.</h1>
<div class="cols">
<section class="card" aria-label="What the agent said">
<p class="label">What the agent said</p>
<p class="{_said_class(summary)}">{_e(summary.strip())}</p>
<p class="who">{_e(a.agent)} · final summary, verbatim</p>
</section>
<section class="card" aria-label="What the log shows">
<p class="label">What the log shows</p>
<div class="stats">
<div class="stat"><b>{a.calls}</b><span>tool calls</span></div>
<div class="stat"><b>{a.allowed}</b><span>allowed</span></div>
<div class="stat deny"><b>{a.denied}</b><span>denied</span></div>
</div>
{''.join(deny_rows)}
<dl class="facts">
<dt>Files written</dt><dd>{listing(a.files_written)}</dd>
<dt>Hosts contacted</dt><dd>{listing(a.hosts_contacted)}</dd>
<dt>Halted</dt><dd>{halted}</dd>
<dt>Chain</dt><dd>{chain}</dd>
</dl>
</section>
</div>
<p class="note">“Not mentioned” means the agent's summary doesn't contain the path, file name, URL or host the action targeted. It's a plain substring check and doesn't understand meaning, so read the summary yourself. This page was built from <code>{_e(log_name)}</code> and the agent's summary, with no model involved. The summary {_e(bound)}.</p>
<details><summary>Full timeline ({len(tl)} entries)</summary><ol>{''.join(tl)}</ol></details>
</main></body></html>
"""


def write_report(log: str | Path, summary: str, out: str | Path) -> Analysis:
    log = Path(log)
    a = analyze(log, summary)
    try:
        timeline = read_entries(log)
    except ValueError:
        timeline = []
    Path(out).write_text(render_html(a, summary, log.name, timeline), encoding="utf-8")
    return a
