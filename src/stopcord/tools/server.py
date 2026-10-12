"""The real tools, as an MCP server the gateway talks to over stdio.

The agent never reaches this process. The gateway spawns it, decides every
call, and only then forwards. As a second line of defense the file tools also
refuse paths that resolve outside the workspace.

Config comes from the environment the gateway sets:
  STOPCORD_WORKSPACE         workspace root
  STOPCORD_DEPLOY_CREDENTIAL dummy credential file for the deploy tool
  STOPCORD_DEPLOY_OUT        where fake deploys are recorded
"""

from __future__ import annotations

import functools
import os
import shlex
import subprocess
from pathlib import Path

import httpx
from mcp.server import MCPServer
from mcp.server.mcpserver.exceptions import ToolError

MAX_OUTPUT = 20_000

mcp = MCPServer("stopcord-tools")


def tool(fn):
    """Register a tool whose ordinary failures come back as a short, readable error."""

    @functools.wraps(fn)
    def wrapper(*args, **kwargs):
        try:
            return fn(*args, **kwargs)
        except ToolError:
            raise
        except (OSError, ValueError, UnicodeError, subprocess.SubprocessError, httpx.HTTPError) as e:
            raise ToolError(f"{type(e).__name__}: {e}") from None

    return mcp.tool()(wrapper)


def _workspace() -> Path:
    return Path(os.environ["STOPCORD_WORKSPACE"]).resolve()


def _inside(raw: str) -> Path:
    ws = _workspace()
    p = (ws / raw).resolve()
    if p != ws and ws not in p.parents:
        raise ToolError("path is outside the workspace")
    return p


def _clip(text: str) -> str:
    return text if len(text) <= MAX_OUTPUT else text[:MAX_OUTPUT] + f"\n… [{len(text) - MAX_OUTPUT} more chars]"


@tool
def read_file(path: str) -> str:
    """Read a text file. Paths are relative to the workspace root."""
    return _clip(_inside(path).read_text(errors="replace"))


@tool
def write_file(path: str, content: str) -> str:
    """Create or overwrite a text file. Paths are relative to the workspace root."""
    p = _inside(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(content)
    return f"wrote {len(content.encode())} bytes to {path}"


@tool
def list_dir(path: str = ".") -> str:
    """List a directory. Paths are relative to the workspace root."""
    p = _inside(path)
    rows = []
    for child in sorted(p.iterdir()):
        if child.name in ("__pycache__", ".pytest_cache", ".git"):
            continue
        rows.append(child.name + ("/" if child.is_dir() else ""))
    return "\n".join(rows) or "(empty)"


@tool
def run_command(command: str) -> str:
    """Run a command in the workspace root, without a shell. Returns exit code and output."""
    argv = shlex.split(command)
    if not argv:
        raise ValueError("empty command")
    env = {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "HOME": os.environ.get("HOME", "/tmp"),
        "LANG": "C.UTF-8",
        "PYTHONDONTWRITEBYTECODE": "1",
        "GIT_PAGER": "cat",
        "NO_COLOR": "1",
    }
    proc = subprocess.run(argv, cwd=_workspace(), env=env, capture_output=True, text=True, timeout=120)
    return _clip(f"exit code {proc.returncode}\n{proc.stdout}{proc.stderr}")


@tool
def http_request(url: str, method: str = "GET", body: str | None = None) -> str:
    """Make an HTTP request. Returns status and the start of the body."""
    r = httpx.request(method, url, content=body, timeout=5.0, follow_redirects=False)
    return _clip(f"HTTP {r.status_code}\n{r.text}")


@tool
def deploy(environment: str) -> str:
    """Deploy the workspace to an environment (staging or prod)."""
    cred = Path(os.environ["STOPCORD_DEPLOY_CREDENTIAL"]).read_text().strip()
    out = Path(os.environ["STOPCORD_DEPLOY_OUT"])
    out.mkdir(parents=True, exist_ok=True)
    (out / f"{environment}.txt").write_text(f"deployed {_workspace().name} to {environment}\n")
    return f"deployed to {environment} (credential ending …{cred[-4:]})"


def main() -> None:
    mcp.run()


if __name__ == "__main__":
    main()
