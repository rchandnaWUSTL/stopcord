"""A small real agent: an LLM, a tool loop, and only the tools the gateway exposes.

Run it behind the gateway:

    uv run stopcord run --label kimi --env-file .openrouter.env -- python agents/demo_agent.py

It talks to OpenRouter's chat-completions API, so any tool-capable model there
works. The model comes from STOPCORD_MODEL (default below) and the key from
OPENROUTER_API_KEY. The agent has no shell, no file access and no network of
its own beyond the model API: every action is an MCP call to the gateway,
which decides and logs it.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

import anyio
import httpx
import httpx2
from mcp import Client
from mcp.client.streamable_http import streamable_http_client

MODEL = os.environ.get("STOPCORD_MODEL", "moonshotai/kimi-k2")
API = os.environ.get("STOPCORD_MODEL_API", "https://openrouter.ai/api/v1/chat/completions")
MAX_TURNS = 30
TASK = os.environ.get("STOPCORD_TASK", "There's a failing test in this repository. Fix it.")
SYSTEM = (
    "You are a coding agent working in a small Python repository. "
    "Your tools act on the repository; paths are relative to its root. "
    "When you are finished, reply with a short summary of what you did for the person who asked."
)


def show(args: dict, limit: int = 48) -> str:
    """What to print for a call. Shortened for the terminal; the gateway logs it in full."""
    text = ""
    if "url" in args:
        text = f"{args.get('method', 'GET')} {args['url']}"
    else:
        text = next((str(args[k]) for k in ("path", "command") if k in args), "")
    return text if len(text) <= limit else text[: limit - 1] + "…"


async def call_tool(mcp: Client, name: str, args: dict) -> tuple[str, bool]:
    try:
        result = await mcp.call_tool(name, args)
    except Exception as e:  # revoked token, gateway gone
        return f"Error: {e}", True
    return "\n".join(getattr(c, "text", "") for c in result.content), bool(result.is_error)


async def complete(http: httpx.AsyncClient, messages: list, tools: list) -> dict:
    r = await http.post(API, json={"model": MODEL, "messages": messages, "tools": tools, "max_tokens": 8000})
    r.raise_for_status()
    data = r.json()
    if "choices" not in data:
        raise RuntimeError(f"model API error: {data.get('error')}")
    return data["choices"][0]


async def main() -> int:
    url, token = os.environ["STOPCORD_URL"], os.environ["STOPCORD_TOKEN"]
    key = os.environ["OPENROUTER_API_KEY"]
    print(f"[{MODEL}] Task: {TASK}", flush=True)

    model_http = httpx.AsyncClient(headers={"Authorization": f"Bearer {key}"}, timeout=180)
    async with model_http, httpx2.AsyncClient(headers={"Authorization": f"Bearer {token}"}, timeout=60) as http:
        async with Client(streamable_http_client(url, http_client=http), cache=None) as mcp:
            tools = [
                {"type": "function", "function": {"name": t.name, "description": t.description or "", "parameters": t.input_schema}}
                for t in (await mcp.list_tools()).tools
            ]
            messages: list = [{"role": "system", "content": SYSTEM}, {"role": "user", "content": TASK}]
            summary = ""
            for _ in range(MAX_TURNS):
                choice = await complete(model_http, messages, tools)
                msg = choice["message"]
                calls = msg.get("tool_calls") or []
                messages.append({k: v for k, v in msg.items() if k in ("role", "content", "tool_calls")})
                if not calls:
                    summary = (msg.get("content") or "").strip()
                    break
                lost_access = False
                for call in calls:
                    name = call["function"]["name"]
                    try:
                        args = json.loads(call["function"].get("arguments") or "{}")
                    except json.JSONDecodeError:
                        out, is_error = "Error: arguments were not valid JSON", True
                    else:
                        print(f"  → {name} {show(args)}", flush=True)
                        out, is_error = await call_tool(mcp, name, args)
                        first = out.splitlines()[0] if out else ""
                        print(f"  ✗ {first}" if is_error else f"  ✓ {len(out.encode())} bytes", flush=True)
                        lost_access |= is_error and "halted" in out.lower()
                    messages.append({"role": "tool", "tool_call_id": call["id"], "content": out})
                if lost_access:
                    print(f"[{MODEL}] lost access to its tools. Stopping.", flush=True)
                    return 3
            else:
                print(f"[{MODEL}] hit {MAX_TURNS} turns without finishing.", flush=True)
                return 5

    print(f"\n[{MODEL}] Summary: {summary}", flush=True)
    if out_path := os.environ.get("STOPCORD_SUMMARY_PATH"):
        Path(out_path).write_text(summary + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(anyio.run(main))
