"""Policy: parse policy.yaml and decide every tool call.

`decide()` is a pure function. No I/O, no model, no randomness. Anything that
needs the filesystem (resolving `..` and symlinks) happens earlier, in
`normalize()`, and is handed to `decide()` as plain data.
"""

from __future__ import annotations

import fnmatch
import hashlib
import shlex
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import Any
from urllib.parse import urlsplit

import yaml

FS_TOOLS = ("read_file", "write_file", "list_dir")
PATH_ARG = "path"

ALLOW = "allow"
DENY = "deny"

# Rule ids the gateway fires on its own, before any policy rule.
RULE_BUDGET = "budget"
RULE_PROTECTED = "gateway-protected"
RULE_BAD_REQUEST = "bad-request"
RULE_DEFAULT = "default-deny"


class PolicyError(ValueError):
    pass


@dataclass(frozen=True)
class Rule:
    id: str
    effect: str
    tools: tuple[str, ...] = ("*",)
    paths: tuple[str, ...] | None = None
    outside_workspace: bool | None = None
    hosts: tuple[str, ...] | None = None
    commands: tuple[tuple[str, ...], ...] | None = None
    args: tuple[tuple[str, Any], ...] | None = None
    reason: str | None = None


@dataclass(frozen=True)
class Policy:
    rules: tuple[Rule, ...]
    budget: int
    name: str = "policy"
    sha256: str = ""


@dataclass(frozen=True)
class Request:
    """A tool call after normalization. Built by `normalize()`, read by `decide()`."""

    tool: str
    args: dict[str, Any]
    path: str | None = None  # workspace-relative posix path, symlinks and .. resolved
    outside_workspace: bool = False
    protected: bool = False  # resolves into the log dir, policy file or gateway state
    host: str | None = None
    argv: tuple[str, ...] | None = None
    error: str | None = None  # the request could not be normalized

    @property
    def target(self) -> str | None:
        """The one string a human would use to name what this call touches."""
        if self.path is not None:
            return self.path
        if self.host is not None:
            return self.host
        if self.argv is not None:
            return shlex.join(self.argv)
        return None


@dataclass(frozen=True)
class Decision:
    allowed: bool
    rule_id: str
    reason: str | None = None

    @property
    def effect(self) -> str:
        return ALLOW if self.allowed else DENY


# ---------------------------------------------------------------------------
# Loading


def _as_tuple(value: Any, what: str) -> tuple[str, ...]:
    if isinstance(value, str):
        return (value,)
    if isinstance(value, list) and all(isinstance(v, str) for v in value):
        return tuple(value)
    raise PolicyError(f"{what} must be a string or a list of strings")


def parse_policy(text: str, name: str = "policy") -> Policy:
    data = yaml.safe_load(text) or {}
    if not isinstance(data, dict):
        raise PolicyError("policy must be a mapping")
    budget = data.get("budget", 100)
    if not isinstance(budget, int) or budget < 1:
        raise PolicyError("budget must be a positive integer")

    rules: list[Rule] = []
    seen: set[str] = set()
    for i, raw in enumerate(data.get("rules") or []):
        if not isinstance(raw, dict):
            raise PolicyError(f"rule {i} must be a mapping")
        rid = raw.get("id")
        if not isinstance(rid, str) or not rid:
            raise PolicyError(f"rule {i} needs an id")
        if rid in seen:
            raise PolicyError(f"duplicate rule id {rid!r}")
        seen.add(rid)
        effect = raw.get("effect")
        if effect not in (ALLOW, DENY):
            raise PolicyError(f"rule {rid}: effect must be allow or deny")
        match = raw.get("match") or {}
        if not isinstance(match, dict):
            raise PolicyError(f"rule {rid}: match must be a mapping")
        unknown = set(match) - {"paths", "outside_workspace", "hosts", "commands", "args"}
        if unknown:
            raise PolicyError(f"rule {rid}: unknown match keys {sorted(unknown)}")

        commands = None
        if "commands" in match:
            commands = tuple(tuple(shlex.split(c)) for c in _as_tuple(match["commands"], f"rule {rid}: commands"))
        args = None
        if "args" in match:
            if not isinstance(match["args"], dict):
                raise PolicyError(f"rule {rid}: args must be a mapping")
            args = tuple(sorted(match["args"].items()))
        outside = match.get("outside_workspace")
        if outside is not None and not isinstance(outside, bool):
            raise PolicyError(f"rule {rid}: outside_workspace must be true or false")

        rules.append(
            Rule(
                id=rid,
                effect=effect,
                tools=_as_tuple(raw.get("tool", "*"), f"rule {rid}: tool"),
                paths=_as_tuple(match["paths"], f"rule {rid}: paths") if "paths" in match else None,
                outside_workspace=outside,
                hosts=tuple(h.lower() for h in _as_tuple(match["hosts"], f"rule {rid}: hosts")) if "hosts" in match else None,
                commands=commands,
                args=args,
                reason=raw.get("reason"),
            )
        )
    return Policy(
        rules=tuple(rules),
        budget=budget,
        name=str(data.get("name", name)),
        sha256=hashlib.sha256(text.encode()).hexdigest(),
    )


def load_policy(path: str | Path) -> Policy:
    p = Path(path)
    return parse_policy(p.read_text(), name=p.stem)


# ---------------------------------------------------------------------------
# Deciding (pure)


def _path_matches(path: str, pattern: str) -> bool:
    """A pattern matches the whole relative path or its last component.

    fnmatch's `*` crosses `/`, so `src/*` covers everything under src/, and
    `*secret*` catches a secret anywhere in the path. `**` is accepted as `*`.
    """
    pattern = pattern.replace("**", "*")
    return fnmatch.fnmatchcase(path, pattern) or fnmatch.fnmatchcase(PurePosixPath(path).name, pattern)


def _host_matches(host: str, pattern: str) -> bool:
    if pattern.startswith("*."):
        return host.endswith(pattern[1:])
    return host == pattern or pattern == "*"


def _rule_matches(rule: Rule, req: Request) -> bool:
    if "*" not in rule.tools and req.tool not in rule.tools:
        return False
    if rule.outside_workspace is not None and req.outside_workspace != rule.outside_workspace:
        return False
    if rule.paths is not None:
        if req.path is None or req.outside_workspace:
            return False
        if not any(_path_matches(req.path, p) for p in rule.paths):
            return False
    if rule.hosts is not None:
        if req.host is None or not any(_host_matches(req.host, h) for h in rule.hosts):
            return False
    if rule.commands is not None:
        if req.argv is None or req.argv not in rule.commands:
            return False
    if rule.args is not None:
        if any(req.args.get(k) != v for k, v in rule.args):
            return False
    return True


def decide(policy: Policy, req: Request, calls_so_far: int = 0) -> Decision:
    """Decide one call. Default deny, rules top to bottom, first match wins."""
    if calls_so_far >= policy.budget:
        return Decision(False, RULE_BUDGET, f"call budget of {policy.budget} used up")
    if req.error is not None:
        return Decision(False, RULE_BAD_REQUEST, req.error)
    if req.protected:
        return Decision(False, RULE_PROTECTED, "path belongs to the gateway")
    for rule in policy.rules:
        if _rule_matches(rule, req):
            return Decision(rule.effect == ALLOW, rule.id, rule.reason)
    return Decision(False, RULE_DEFAULT, "no rule matched")


def denial_message(decision: Decision) -> str:
    """What the agent is told. The rule id only, never the policy text."""
    return f"Denied by policy (rule {decision.rule_id})."


# ---------------------------------------------------------------------------
# Normalizing (does I/O; kept out of decide)


def _inside(child: Path, parent: Path) -> bool:
    return child == parent or parent in child.parents


@dataclass
class Normalizer:
    workspace: Path
    protected: tuple[Path, ...] = field(default_factory=tuple)

    def __post_init__(self) -> None:
        self.workspace = Path(self.workspace).resolve()
        self.protected = tuple(Path(p).resolve() for p in self.protected)

    def resolve_path(self, raw: str) -> tuple[str, bool, bool]:
        """Return (display path, outside_workspace, protected).

        Resolves `..` and every symlink on the way, including the last
        component. A path that doesn't exist yet resolves through its parent.
        """
        resolved = (self.workspace / raw).resolve(strict=False)
        protected = any(_inside(resolved, p) for p in self.protected)
        if _inside(resolved, self.workspace):
            rel = resolved.relative_to(self.workspace).as_posix()
            return (rel if rel != "." else "."), False, protected
        return str(resolved), True, protected

    def normalize(self, tool: str, args: dict[str, Any]) -> Request:
        args = dict(args or {})
        try:
            if tool in FS_TOOLS:
                raw = args.get(PATH_ARG, ".")
                if not isinstance(raw, str) or "\x00" in raw:
                    return Request(tool, args, error="path must be a string")
                path, outside, protected = self.resolve_path(raw)
                return Request(tool, args, path=path, outside_workspace=outside, protected=protected)
            if tool == "run_command":
                cmd = args.get("command")
                if not isinstance(cmd, str):
                    return Request(tool, args, error="command must be a string")
                return Request(tool, args, argv=tuple(shlex.split(cmd)))
            if tool == "http_request":
                url = args.get("url")
                if not isinstance(url, str):
                    return Request(tool, args, error="url must be a string")
                host = (urlsplit(url).hostname or "").lower().rstrip(".")
                if not host:
                    return Request(tool, args, error="url has no host")
                return Request(tool, args, host=host)
        except (ValueError, OSError) as e:
            return Request(tool, args, error=f"could not parse arguments: {e}")
        return Request(tool, args)
