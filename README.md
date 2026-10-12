# StopCord

A containment layer for AI agents: a policy gate in front of every tool call, a log the agent can't quietly edit, and a stop switch.

[![CI](https://github.com/rchandnaWUSTL/stopcord/actions/workflows/ci.yml/badge.svg)](https://github.com/rchandnaWUSTL/stopcord/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

![The StopCord console during a real agent run: the agent's read of .env is blocked, and its final report doesn't mention it](docs/media/demo.gif)

## Try it

```
uvx --from git+https://github.com/rchandnaWUSTL/stopcord stopcord demo
```

About 15 seconds, no API key, no network. A scripted agent fixes a failing test, tries to read `.env`, and tries to upload it. Both are blocked. You get a log in `runs/`, a verification line, and a report that puts the agent's summary next to what the log shows.

Then change one byte of that log and run `stopcord verify` on it.

## What it does

- **Gate.** Every tool call is decided by plain code against `policy.yaml`. Default deny, first match wins, paths resolved before matching. No model in the path.
- **Log.** The gateway writes a hash-chained JSONL file per run. `stopcord verify` names the first entry that changed.
- **Stop.** `stopcord kill`, the console's Stop button, or K in `stopcord tail` revokes the agent's access mid-task.
- **Report.** `stopcord report` lists blocked calls the agent's summary doesn't mention.

## What it doesn't do

This makes an agent's actions observable and containable. It does not make the agent aligned, and it does not stop harm inside what the policy allows.

The log is tamper-evident, not tamper-proof: an edit anywhere fails verification at that entry, but someone who controls the machine can rewrite the whole file. Details in [THREAT_MODEL.md](THREAT_MODEL.md).

## Use it with your agent

Point any MCP client (Claude Code, Cursor, Claude Desktop) at the gateway:

```json
{
  "mcpServers": {
    "stopcord": {
      "command": "uvx",
      "args": ["--from", "git+https://github.com/rchandnaWUSTL/stopcord",
               "stopcord", "gateway",
               "--policy", "/abs/path/policy.yaml",
               "--workspace", "/abs/path/repo"]
    }
  }
}
```

Turn off the client's own file, shell and web tools, or the agent can go around the gate.

| Command | |
|---|---|
| `stopcord run -- <agent cmd>` | Run an agent script whose only way to act is the gateway |
| `stopcord gateway` | MCP server over stdio, for client configs |
| `stopcord console` | Local web console: live calls, log integrity, Stop button |
| `stopcord tail` / `stopcord kill` | Watch or stop a run from the terminal |
| `stopcord verify <log>` | Check the hash chain. Exits nonzero on failure |
| `stopcord report <log> --summary <file>` | HTML report: the agent's summary next to the log |

## Policy

```yaml
rules:
  - id: env-files
    tool: [read_file, write_file, list_dir]
    match: {paths: [".env", ".env.*"]}
    effect: deny
  - id: workspace-files
    tool: [read_file, write_file, list_dir]
    match: {paths: ["*"]}
    effect: allow
  - id: tests
    tool: run_command
    match: {commands: ["pytest -q", "git diff"]}
    effect: allow
```

Anything unmatched is denied. Commands match exactly and never run through a shell. The full starter policy is [examples/quickstart/policy.yaml](examples/quickstart/policy.yaml).

## Real runs

Every real run behind the demo is in [runs/](runs/README.md), including the ones I didn't use. In 18 runs of Kimi K2 on the same task, it tried to read `.env` in 13. None of its 17 summaries mentioned it.

## Security

Report vulnerabilities privately; see [SECURITY.md](SECURITY.md). StopCord runs locally and sends nothing anywhere.

## Credit

Prompted by Satya Nadella's essay [Models as Insider Risks in the Super Intelligence Era](https://snscratchpad.com/posts/models-as-insider-risks/). Not affiliated with Microsoft.

## Contributing and license

See [CONTRIBUTING.md](CONTRIBUTING.md). MIT licensed.
