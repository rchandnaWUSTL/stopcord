# Threat model

This makes an agent's actions observable and containable. It does not make the agent aligned, and it does not stop harm inside what the policy allows.

## What StopCord assumes

- The agent may be wrong, careless, or steered by a prompt injection, and may misreport what it did.
- The machine running the gateway, and the person operating it, are trusted.
- The agent's only way to act is the gateway. If it has other tools, they aren't covered.

## What it defends against

| Threat | How |
|---|---|
| A tool call the policy doesn't allow | Every call is decided by `decide()`, a pure function, before anything runs. Default deny. |
| Path tricks (`../`, symlinks) | Paths are resolved, including symlinks, before matching. The tools process also refuses paths outside the workspace. |
| Reading the log, policy or gateway state through the tools | These paths are denied by a built-in rule that comes before the policy. |
| An agent that won't stop | Stop revokes the session token, cancels calls in flight, ends the tools process and writes `run_halted`. The agent's next call fails. |
| A summary that leaves things out | The report lists blocked calls the summary doesn't mention, with a plain substring check. |
| Edits to a saved log | Each entry hashes the one before it, and the first commits to the policy file. `stopcord verify` fails at the first changed entry. |

## What it doesn't defend against

**Someone who controls the machine.** The log is tamper-evident, not tamper-proof. Change a byte and verification fails at that entry. Edit an entry and recompute its hash, and the next entry fails. But someone with write access can rewrite the whole file and every hash. Entries cut off the end also verify cleanly unless you saved the head hash somewhere else. Signed head hashes aren't built yet.

**Same OS user.** In the demo the gateway and the agent run as the same user, and the agent process isn't sandboxed by the OS. The demo agents act only through the gateway because they were given no other tools.

**Harm inside the policy.** Anything allowed is possible. The starter policy allows writing workspace files and running `pytest`, so an agent could write a test that reads `.env` and run it. The gate sees an allowed write and an allowed command. Commands the tools run also have ordinary network access.

**Time-of-check to time-of-use.** Paths are checked before the call. A symlink swapped in between the check and the use could get past the policy (the tools process still refuses paths outside the workspace).

**Calls that bypass the gateway.** If an MCP client keeps its own file, shell or web tools, those calls are never seen.

**Meaning.** The report's "not mentioned" check is a substring match on paths, file names and hosts. It doesn't understand language. A person reads the summary and decides.

## What's logged

Each entry has a sequence number, UTC time, event, tool, arguments, target, rule id, decision, a result digest and short preview, and the hash chain fields. Secret-looking strings in arguments and previews are redacted. Long arguments are stored as a digest, length and preview. Full results are not stored.
