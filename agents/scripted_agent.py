"""Scripted agent (test fixture). The real code is in stopcord.agents.scripted
so `stopcord demo` works from an installed package.

    uv run stopcord run -- python agents/scripted_agent.py fix
"""

from stopcord.agents.scripted import cli

if __name__ == "__main__":
    cli()
