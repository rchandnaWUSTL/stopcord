"""Hash-chained action log and its verifier.

One JSONL file per run. Each entry's hash is sha256(prev_hash + canonical JSON
of the entry without its own hash). The first entry's prev_hash commits to the
policy file and the gateway version, so a log proves which rules were in force.

Tamper-evident, not tamper-proof: change a byte and verification fails at that
entry, but someone who controls the machine can rewrite the whole file.
"""

from __future__ import annotations

import hashlib
import json
import os
import threading
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

EVENTS = ("run_started", "tool_requested", "policy_decision", "tool_result", "run_halted", "run_finished")
TERMINAL_EVENTS = ("run_halted", "run_finished")
FIELDS = (
    "seq",
    "ts",
    "run_id",
    "event",
    "tool",
    "args",
    "target",
    "rule_id",
    "decision",
    "result_digest",
    "result_preview",
    "summary",
    "detail",
    "prev_hash",
)


def canonical_json(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def sha256_hex(data: str | bytes) -> str:
    if isinstance(data, str):
        data = data.encode()
    return hashlib.sha256(data).hexdigest()


def genesis_hash(policy_sha256: str, gateway_version: str) -> str:
    return sha256_hex(f"agentreceipts-genesis\npolicy={policy_sha256}\ngateway={gateway_version}\n")


def entry_hash(entry: dict[str, Any]) -> str:
    body = {k: v for k, v in entry.items() if k != "hash"}
    return sha256_hex(body["prev_hash"] + canonical_json(body))


def utc_now() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


class ChainWriter:
    """Append-only writer. Only the gateway process holds one."""

    def __init__(self, path: Path, run_id: str, policy_sha256: str, gateway_version: str):
        self.path = Path(path)
        self.run_id = run_id
        self.path.parent.mkdir(parents=True, exist_ok=True)
        if self.path.exists():
            raise FileExistsError(f"log already exists: {self.path}")
        self._fh = open(self.path, "x", encoding="utf-8")
        self._lock = threading.Lock()
        self.seq = 0
        self.head = genesis_hash(policy_sha256, gateway_version)
        self.closed = False

    def append(self, event: str, **fields: Any) -> dict[str, Any]:
        if event not in EVENTS:
            raise ValueError(f"unknown event {event}")
        with self._lock:
            if self.closed:
                raise RuntimeError("log is closed")
            self.seq += 1
            entry: dict[str, Any] = {k: None for k in FIELDS}
            entry.update(fields)
            entry.update(seq=self.seq, ts=utc_now(), run_id=self.run_id, event=event, prev_hash=self.head)
            entry["hash"] = entry_hash(entry)
            self._fh.write(canonical_json(entry) + "\n")
            self._fh.flush()
            os.fsync(self._fh.fileno())
            self.head = entry["hash"]
            return entry

    def close(self) -> None:
        with self._lock:
            if not self.closed:
                self.closed = True
                self._fh.close()


@dataclass
class VerifyResult:
    ok: bool
    entries: int
    head: str | None
    broken_seq: int | None = None
    reason: str | None = None
    warnings: list[str] = field(default_factory=list)


def read_entries(path: Path) -> list[dict[str, Any]]:
    """Parse a log without checking it. Use `verify()` before trusting the result."""
    out = []
    for line in Path(path).read_bytes().splitlines():
        if line.strip():
            out.append(json.loads(line))
    return out


def verify(path: str | Path, policy_sha256: str | None = None) -> VerifyResult:
    """Recompute the whole chain. Names the first entry that doesn't check out.

    Entries are numbered from 1 by their line in the file, so "entry 14" is
    line 14 even if someone edited the seq field.
    """
    raw = Path(path).read_bytes()
    lines = raw.split(b"\n")
    if lines and lines[-1] == b"":
        lines.pop()
    if not lines:
        return VerifyResult(False, 0, None, None, "log is empty")

    prev: str | None = None
    head: str | None = None
    entry: dict[str, Any] = {}
    for n, line in enumerate(lines, start=1):

        def fail(reason: str) -> VerifyResult:
            return VerifyResult(False, len(lines), head, n, reason)

        try:
            entry = json.loads(line.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            return fail("entry is not valid JSON")
        if not isinstance(entry, dict) or "hash" not in entry or "prev_hash" not in entry:
            return fail("entry is missing hash fields")
        if entry.get("seq") != n:
            return fail(f"seq is {entry.get('seq')!r}, expected {n}")
        if n == 1:
            if entry.get("event") != "run_started":
                return fail("first entry is not run_started")
            detail = entry.get("detail") or {}
            expected = genesis_hash(str(detail.get("policy_sha256")), str(detail.get("gateway_version")))
            if entry["prev_hash"] != expected:
                return fail("prev_hash does not match the policy and gateway version this run declares")
            if policy_sha256 is not None and detail.get("policy_sha256") != policy_sha256:
                return fail("log was written under a different policy file")
        elif entry["prev_hash"] != prev:
            return fail("prev_hash does not match the previous entry")
        try:
            recomputed = entry_hash(entry)
        except (TypeError, KeyError):
            return fail("entry cannot be hashed")
        if recomputed != entry["hash"]:
            return fail("hash does not match the entry's contents")
        prev = head = entry["hash"]

    result = VerifyResult(True, len(lines), head)
    if entry.get("event") not in TERMINAL_EVENTS:
        result.warnings.append("log has no run_finished or run_halted entry (run still going, or truncated)")
    result.warnings.append("a valid chain can still be truncated at the end; compare the head hash to one you saved")
    return result
