"""The gateway: the single point where tool calls are decided, logged and halted.

To the agent it is an MCP server. To the real tools it is an MCP client. Every
call goes: token check, normalize, tool_requested, decide, policy_decision,
then forward or deny, then tool_result. Nothing in this file calls a model.
"""

from __future__ import annotations

import contextlib
import hashlib
import hmac
import os
import shutil
import socket
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import anyio
import mcp.types as types
import uvicorn
from mcp import Client, StdioServerParameters
from mcp.server import Server

from stopcord import __version__, control, summaries
from stopcord.chain import ChainWriter, canonical_json
from stopcord.policy import Normalizer, decide, denial_message, load_policy
from stopcord.redact import digest, preview, redact

LONG_ARG = 400  # string args longer than this are logged as a digest plus a preview
HALT_GRACE_SECONDS = 15


@dataclass
class RunConfig:
    policy_path: Path
    workspace: Path
    runs_dir: Path
    run_id: str = field(default_factory=control.new_run_id)
    agent_label: str = "agent"
    work_root: Path = Path(".stopcord-work")
    task: str | None = None  # what the operator asked for, recorded in run_started

    def __post_init__(self) -> None:
        self.policy_path = Path(self.policy_path).resolve()
        self.workspace = Path(self.workspace).resolve()
        self.runs_dir = Path(self.runs_dir).resolve()
        self.work_root = Path(self.work_root).resolve()

    @property
    def state_dir(self) -> Path:
        """Gateway-only files for this run: agent summary, dummy deploy credential."""
        return self.work_root / self.run_id / "gateway"

    @property
    def log_path(self) -> Path:
        return self.runs_dir / f"{self.run_id}.jsonl"


def display_path(p: Path) -> str:
    """A path for the log: relative to cwd or ~ when possible, so logs don't carry home dirs."""
    p = Path(p)
    for base, prefix in ((Path.cwd(), ""), (Path.home(), "~/")):
        try:
            return prefix + p.relative_to(base).as_posix()
        except ValueError:
            pass
    if "site-packages" in p.parts:
        return "<site-packages>/" + "/".join(p.parts[p.parts.index("site-packages") + 1 :])
    return str(p)


def error_result(text: str) -> types.CallToolResult:
    return types.CallToolResult(content=[types.TextContent(type="text", text=text)], is_error=True)


def result_text(result: types.CallToolResult) -> str:
    parts = []
    for block in result.content:
        parts.append(getattr(block, "text", None) or canonical_json(block.model_dump(mode="json")))
    return "\n".join(parts)


def log_args(args: dict[str, Any]) -> dict[str, Any]:
    """Arguments as logged: secret-looking strings redacted, long strings digested."""
    out: dict[str, Any] = {}
    for k, v in args.items():
        if isinstance(v, str):
            if len(v) > LONG_ARG:
                out[k] = {"digest": digest(v), "chars": len(v), "preview": preview(v, 120)}
            else:
                out[k] = redact(v)
        else:
            out[k] = v
    return out


class Gateway:
    def __init__(self, cfg: RunConfig):
        self.cfg = cfg
        self.run_id = cfg.run_id
        self.policy_bytes = cfg.policy_path.read_bytes()
        self.policy = load_policy(cfg.policy_path)
        self.token = control.new_token()
        cfg.state_dir.mkdir(parents=True, exist_ok=True)
        self.normalizer = Normalizer(
            cfg.workspace,
            protected=(cfg.runs_dir, cfg.policy_path, cfg.state_dir, control.state_root()),
        )
        self.log = ChainWriter(cfg.log_path, cfg.run_id, self.policy.sha256, __version__)
        self.calls = self.allowed = self.denied = 0
        self.halted = anyio.Event()
        self.halt_done = anyio.Event()
        self.finished = False
        self.halt_reply: dict[str, Any] | None = None
        self._lock = anyio.Lock()
        self._inflight: set[anyio.CancelScope] = set()
        self._stop_upstream = anyio.Event()
        self._upstream_closed = anyio.Event()
        self.upstream: Client | None = None
        self.url: str | None = None
        self.tools: list[types.Tool] = []
        self.server = Server("stopcord", version=__version__, on_list_tools=self._on_list_tools, on_call_tool=self._on_call_tool)

    # -- upstream tools -----------------------------------------------------

    def _upstream_params(self) -> StdioServerParameters:
        cred = self.cfg.state_dir / "deploy-credential.txt"
        if not cred.exists():
            cred.write_text("DUMMY-deploy-credential-for-the-demo-0000\n")
            cred.chmod(0o600)
        bindir = str(Path(sys.executable).parent)
        return StdioServerParameters(
            command=sys.executable,
            args=["-m", "stopcord.tools.server"],
            cwd=str(self.cfg.workspace),
            env={
                "PATH": bindir + os.pathsep + os.environ.get("PATH", "/usr/bin:/bin"),
                **({"PYTHONPATH": os.environ["PYTHONPATH"]} if "PYTHONPATH" in os.environ else {}),
                "STOPCORD_WORKSPACE": str(self.cfg.workspace),
                "STOPCORD_DEPLOY_CREDENTIAL": str(cred),
                "STOPCORD_DEPLOY_OUT": str(self.cfg.state_dir / "deploys"),
            },
        )

    async def _run_upstream(self, *, task_status=anyio.TASK_STATUS_IGNORED) -> None:
        try:
            async with Client(self._upstream_params(), cache=None) as client:
                self.upstream = client
                self.tools = list((await client.list_tools()).tools)
                task_status.started()
                await self._stop_upstream.wait()
        finally:
            self.upstream = None
            self._upstream_closed.set()

    async def start(self, tg: anyio.abc.TaskGroup) -> None:
        await tg.start(self._run_upstream)
        self.log.append(
            "run_started",
            summary=summaries.run_started(self.cfg.agent_label, self.policy.name, len(self.policy.rules), self.policy.budget),
            detail={
                "gateway_version": __version__,
                "policy_sha256": self.policy.sha256,
                "policy_path": display_path(self.cfg.policy_path),
                "policy_name": self.policy.name,
                "workspace": display_path(self.cfg.workspace),
                "agent": self.cfg.agent_label,
                "task": self.cfg.task,
                "tools": [t.name for t in self.tools],
                "budget": self.policy.budget,
            },
        )

    # -- the enforcement point ---------------------------------------------

    async def _on_list_tools(self, ctx, params) -> types.ListToolsResult:
        return types.ListToolsResult(tools=self.tools)

    async def _on_call_tool(self, ctx, params: types.CallToolRequestParams) -> types.CallToolResult:
        return await self.call_tool(params.name, params.arguments or {})

    async def call_tool(self, name: str, args: dict[str, Any]) -> types.CallToolResult:
        async with self._lock:
            if self.halted.is_set() or self.finished:
                return error_result("Run halted. Session token revoked.")
            req = self.normalizer.normalize(name, args)
            target = req.target
            shown = target
            if req.host is not None:
                shown = f"{str(args.get('method') or 'GET').upper()} {redact(str(args.get('url')))}"
            logged = log_args(args)
            self.log.append("tool_requested", tool=name, args=logged, target=target, summary=summaries.tool_requested(name, shown))
            d = decide(self.policy, req, self.calls)
            self.calls += 1
            self.log.append(
                "policy_decision",
                tool=name,
                args=logged,
                target=target,
                rule_id=d.rule_id,
                decision=d.effect,
                summary=summaries.policy_decision(name, shown, d.allowed, d.rule_id),
                detail={"outside_workspace": req.outside_workspace, "raw_path": args.get("path")} if req.path is not None else None,
            )
            if not d.allowed:
                self.denied += 1
                return error_result(denial_message(d))
            self.allowed += 1
            scope = anyio.CancelScope()
            self._inflight.add(scope)

        result: types.CallToolResult | None = None
        try:
            with scope:
                if self.upstream is None:
                    raise RuntimeError("upstream tools are not running")
                result = await self.upstream.call_tool(name, args)
        except Exception as e:
            result = error_result(f"Tool failed: {type(e).__name__}: {e}")
        finally:
            if scope.cancelled_caught or result is None:
                result = error_result("Run halted mid-call. Session token revoked.")
            text = result_text(result)
            if not self.log.closed:
                self.log.append(
                    "tool_result",
                    tool=name,
                    target=target,
                    rule_id=d.rule_id,
                    result_digest=digest(text),
                    result_preview=preview(text),
                    summary=summaries.tool_result(name, shown, not result.is_error, len(text.encode())),
                    detail={"is_error": bool(result.is_error), "bytes": len(text.encode()), "cancelled": scope.cancelled_caught},
                )
            self._inflight.discard(scope)
        return result

    # -- halt and finish ----------------------------------------------------

    async def halt(self, who: str, via: str) -> dict[str, Any]:
        if self.halt_reply is not None:
            return {**self.halt_reply, "already": True}
        if self.finished:
            return {"ok": False, "error": "run already finished"}
        async with self._lock:
            self.halted.set()  # the HTTP guard rejects the token from here on
            cancelled = len(self._inflight)
            for scope in list(self._inflight):
                scope.cancel()
        with anyio.move_on_after(2):
            while self._inflight:
                await anyio.sleep(0.01)
        self._stop_upstream.set()
        with anyio.move_on_after(5):
            await self._upstream_closed.wait()
        entry = self.log.append(
            "run_halted",
            summary=summaries.run_halted(who, via),
            detail={
                "who": who,
                "via": via,
                "in_flight_cancelled": cancelled,
                "upstream_terminated": self._upstream_closed.is_set(),
                "calls": self.calls,
                "allowed": self.allowed,
                "denied": self.denied,
            },
        )
        self.log.close()
        self.halt_reply = {"ok": True, "run_id": self.run_id, "seq": entry["seq"], "ts": entry["ts"], "head": entry["hash"]}
        self.halt_done.set()
        return self.halt_reply

    async def finish(self, exit_code: int | None, summary_sha256: str | None = None) -> dict[str, Any] | None:
        async with self._lock:
            if self.halted.is_set() or self.finished:
                return None
            self.finished = True
        entry = self.log.append(
            "run_finished",
            summary=summaries.run_finished(self.calls, self.allowed, self.denied, exit_code),
            detail={
                "calls": self.calls,
                "allowed": self.allowed,
                "denied": self.denied,
                "exit_code": exit_code,
                "agent_summary_sha256": summary_sha256,
            },
        )
        self.log.close()
        return entry

    async def shutdown(self) -> None:
        self._stop_upstream.set()
        with anyio.move_on_after(5):
            await self._upstream_closed.wait()

    def status(self) -> dict[str, Any]:
        return {
            "ok": True,
            "run_id": self.run_id,
            "halted": self.halted.is_set(),
            "finished": self.finished,
            "calls": self.calls,
            "allowed": self.allowed,
            "denied": self.denied,
            "log": str(self.cfg.log_path),
        }

    # -- HTTP transport -----------------------------------------------------

    def asgi_app(self):
        app = self.server.streamable_http_app()
        expected = f"Bearer {self.token}".encode()

        async def guard(scope, receive, send):
            if scope["type"] == "http":
                auth = dict(scope.get("headers") or []).get(b"authorization", b"")
                if self.halted.is_set() or self.finished or not hmac.compare_digest(auth, expected):
                    reason = "Run halted. Session token revoked." if self.halted.is_set() else "Session token invalid."
                    body = canonical_json({"jsonrpc": "2.0", "id": None, "error": {"code": -32001, "message": reason}}).encode()
                    await send({"type": "http.response.start", "status": 401, "headers": [(b"content-type", b"application/json")]})
                    await send({"type": "http.response.body", "body": body})
                    return
            await app(scope, receive, send)

        return guard


class _QuietUvicorn(uvicorn.Server):
    """Uvicorn without its signal handlers; the run owns Ctrl-C."""

    @contextlib.contextmanager
    def capture_signals(self):
        yield


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def prepare_workspace(source: Path, cfg: RunConfig) -> Path:
    """Copy a fixture workspace for one run and give it a git baseline."""
    dest = cfg.work_root / cfg.run_id / "workspace"
    shutil.copytree(source, dest, ignore=shutil.ignore_patterns("__pycache__", ".pytest_cache"))
    if shutil.which("git"):
        env = {
            **os.environ,
            "GIT_AUTHOR_NAME": "fixture",
            "GIT_AUTHOR_EMAIL": "fixture@example.invalid",
            "GIT_COMMITTER_NAME": "fixture",
            "GIT_COMMITTER_EMAIL": "fixture@example.invalid",
        }
        for argv in (["git", "init", "-q"], ["git", "add", "-A"], ["git", "commit", "-qm", "fixture baseline"]):
            subprocess.run(argv, cwd=dest, env=env, check=False, capture_output=True)
    return dest


PASS_THROUGH_ENV = ("PYTHONPATH", "PATH", "HOME", "LANG", "TERM", "COLUMNS", "LINES", "ANTHROPIC_API_KEY", "OPENROUTER_API_KEY", "STOPCORD_MODEL", "STOPCORD_MODEL_API", "STOPCORD_SCRIPTED_DELAY", "NO_COLOR", "FORCE_COLOR")


@dataclass
class RunOutcome:
    run_id: str
    log_path: Path
    exit_code: int | None
    halted: bool
    summary_path: Path | None
    calls: int
    allowed: int
    denied: int


async def run_agent(cfg: RunConfig, agent_argv: list[str], *, on_ready=None, extra_env: dict[str, str] | None = None) -> RunOutcome:
    """Start the gateway, run the agent against it, and close the log."""
    gw = Gateway(cfg)
    summary_tmp = cfg.state_dir / "agent_summary.txt"
    exit_code: int | None = None
    port = _free_port()
    control.register(cfg.run_id, cfg.log_path)
    try:
        async with anyio.create_task_group() as tg:
            await gw.start(tg)
            await tg.start(control.serve, gw)
            server = _QuietUvicorn(uvicorn.Config(gw.asgi_app(), host="127.0.0.1", port=port, log_level="warning", lifespan="on"))
            server_done = anyio.Event()

            async def serve_http() -> None:
                try:
                    await server.serve()
                finally:
                    server_done.set()

            tg.start_soon(serve_http)
            while not server.started:
                await anyio.sleep(0.02)
            gw.url = f"http://127.0.0.1:{port}/mcp"
            if on_ready:
                on_ready(gw)

            env = {k: os.environ[k] for k in PASS_THROUGH_ENV if k in os.environ}
            env.update(extra_env or {})
            env.update(
                STOPCORD_URL=gw.url,
                STOPCORD_TOKEN=gw.token,
                STOPCORD_RUN_ID=cfg.run_id,
                STOPCORD_SUMMARY_PATH=str(summary_tmp),
                **({"STOPCORD_TASK": cfg.task} if cfg.task else {}),
                PYTHONUNBUFFERED="1",
            )
            proc = await anyio.open_process(agent_argv, env=env, stdin=None, stdout=None, stderr=None)
            exited = anyio.Event()

            async def watch() -> None:
                nonlocal exit_code
                exit_code = await proc.wait()
                exited.set()

            tg.start_soon(watch)
            async with anyio.create_task_group() as race:

                async def first(ev: anyio.Event) -> None:
                    await ev.wait()
                    race.cancel_scope.cancel()

                race.start_soon(first, exited)
                race.start_soon(first, gw.halted)

            if gw.halted.is_set() and not exited.is_set():
                # Let the agent hit the revoked token and exit on its own, then make sure.
                with anyio.move_on_after(HALT_GRACE_SECONDS):
                    await exited.wait()
                if not exited.is_set():
                    proc.terminate()
                    with anyio.move_on_after(3):
                        await exited.wait()
                    if not exited.is_set():
                        proc.kill()
                        await exited.wait()

            if gw.halted.is_set():
                with anyio.move_on_after(10):
                    await gw.halt_done.wait()

            summary_path = None
            summary_sha = None
            if summary_tmp.exists():
                summary_path = cfg.runs_dir / f"{cfg.run_id}.summary.txt"
                data = summary_tmp.read_bytes()
                summary_path.write_bytes(data)
                summary_sha = hashlib.sha256(data).hexdigest()
            await gw.finish(exit_code, summary_sha)
            server.should_exit = True
            with anyio.move_on_after(5):
                await server_done.wait()
            await gw.shutdown()
            await anyio.sleep(0.05)  # let a kill reply finish sending
            tg.cancel_scope.cancel()
    finally:
        control.unregister(cfg.run_id)
        gw.log.close()
    return RunOutcome(cfg.run_id, cfg.log_path, exit_code, gw.halted.is_set(), summary_path, gw.calls, gw.allowed, gw.denied)


async def serve_stdio(cfg: RunConfig) -> None:
    """Serve one MCP client over stdio (Claude Desktop, Cursor, Claude Code)."""
    from mcp.server.stdio import stdio_server

    gw = Gateway(cfg)
    control.register(cfg.run_id, cfg.log_path)
    print(f"stopcord gateway: run {cfg.run_id}, log {cfg.log_path}", file=sys.stderr)
    try:
        async with anyio.create_task_group() as tg:
            await gw.start(tg)
            await tg.start(control.serve, gw)
            async with stdio_server() as (read, write):
                await gw.server.run(read, write, gw.server.create_initialization_options())
            await gw.finish(None)
            await gw.shutdown()
            tg.cancel_scope.cancel()
    finally:
        control.unregister(cfg.run_id)
        gw.log.close()
