"""Run control: session tokens, the kill socket, and the active-run registry.

The gateway listens on a unix socket. `stopcord kill` and the K key in
`stopcord tail` talk to it. Kill revokes the agent's session token, cancels
in-flight calls, terminates the upstream tool process and writes run_halted.
"""

from __future__ import annotations

import getpass
import json
import os
import secrets
import socket
import tempfile
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any

import anyio

if TYPE_CHECKING:
    from stopcord.gateway import Gateway


def state_root() -> Path:
    """Where sockets and the active-run registry live.

    Under the system temp dir, because macOS caps unix socket paths at 104
    bytes and a socket inside the project tree can blow past that.
    """
    root = Path(os.environ.get("STOPCORD_STATE_DIR") or Path(tempfile.gettempdir()) / "stopcord")
    root.mkdir(parents=True, exist_ok=True, mode=0o700)
    return root


def new_run_id() -> str:
    return datetime.now(UTC).strftime("r%Y%m%d-%H%M%S-") + secrets.token_hex(2)


def new_token() -> str:
    return "rcpt_" + secrets.token_urlsafe(24)


def socket_path(run_id: str) -> Path:
    p = state_root() / f"{run_id}.sock"
    if len(str(p)) > 100:  # AF_UNIX limit is 104 on macOS, 108 on Linux
        short = Path("/tmp") / f"stopcord-{os.getuid()}"
        short.mkdir(exist_ok=True, mode=0o700)
        p = short / f"{run_id}.sock"
    return p


def registry_path(run_id: str) -> Path:
    return state_root() / f"{run_id}.json"


def register(run_id: str, log_path: Path) -> None:
    info = {"run_id": run_id, "socket": str(socket_path(run_id)), "log": str(log_path.resolve()), "pid": os.getpid(), "started": time.time()}
    p = registry_path(run_id)
    p.write_text(json.dumps(info))
    p.chmod(0o600)


def unregister(run_id: str) -> None:
    for p in (registry_path(run_id), socket_path(run_id)):
        p.unlink(missing_ok=True)


def active_runs() -> list[dict[str, Any]]:
    """Registered runs whose socket still answers, newest first."""
    out = []
    for p in state_root().glob("r*.json"):
        try:
            info = json.loads(p.read_text())
        except (OSError, json.JSONDecodeError):
            continue
        if Path(info.get("socket", "")).exists():
            out.append(info)
    return sorted(out, key=lambda i: i["started"], reverse=True)


def find_run(run_id: str | None) -> dict[str, Any] | None:
    runs = active_runs()
    if run_id is None:
        return runs[0] if runs else None
    for info in runs:
        if info["run_id"] == run_id:
            return info
    return None


def send(run_id: str, message: dict[str, Any], timeout: float = 5.0) -> dict[str, Any]:
    """Send one control message and return the gateway's reply."""
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
        s.settimeout(timeout)
        s.connect(str(socket_path(run_id)))
        s.sendall(json.dumps(message).encode() + b"\n")
        buf = b""
        while not buf.endswith(b"\n"):
            chunk = s.recv(4096)
            if not chunk:
                break
            buf += chunk
    return json.loads(buf or b"{}")


def kill(run_id: str, via: str = "cli") -> dict[str, Any]:
    return send(run_id, {"cmd": "kill", "who": getpass.getuser(), "via": via})


async def serve(gw: Gateway, *, task_status=anyio.TASK_STATUS_IGNORED) -> None:
    path = socket_path(gw.run_id)
    path.unlink(missing_ok=True)
    listener = await anyio.create_unix_listener(path)
    path.chmod(0o600)
    task_status.started()

    async def handle(stream) -> None:
        # Shielded: once a kill has started, finishing it and answering matter more than shutdown.
        with anyio.CancelScope(shield=True):
            await _handle(stream)

    async def _handle(stream) -> None:
        async with stream:
            try:
                raw = b""
                while not raw.endswith(b"\n") and len(raw) < 65536:
                    raw += await stream.receive(4096)
                msg = json.loads(raw)
                if msg.get("cmd") == "kill":
                    reply = await gw.halt(who=str(msg.get("who", "unknown")), via=str(msg.get("via", "socket")))
                elif msg.get("cmd") == "status":
                    reply = gw.status()
                else:
                    reply = {"ok": False, "error": "unknown command"}
            except Exception as e:  # never let a bad client take down the gateway
                reply = {"ok": False, "error": str(e)}
            await stream.send(json.dumps(reply).encode() + b"\n")

    async with listener:
        await listener.serve(handle)
