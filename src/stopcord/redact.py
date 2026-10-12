"""Result digests and previews, with secret-looking strings redacted."""

from __future__ import annotations

import hashlib
import re

PREVIEW_CHARS = 160

_PATTERNS = [
    # KEY=value / KEY: value where the key name looks sensitive
    re.compile(
        r"(?im)\b([A-Z0-9_]*(?:SECRET|TOKEN|PASSWORD|PASSWD|PRIVATE|CREDENTIAL|API_?KEY|ACCESS_?KEY)[A-Z0-9_]*)"
        r"(\s*[=:]\s*)(\"?)[^\s\"']+"
    ),
    re.compile(r"\b(sk|rk|pk)_(live|test)_[A-Za-z0-9_\-]{6,}"),
    re.compile(r"\bsk-[A-Za-z0-9_\-]{12,}"),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}"),
    re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._\-]{12,}"),
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----"),
    re.compile(r"\b[a-z]+://[^\s:/@]+:[^\s@/]+@"),  # credentials in URLs
]


def redact(text: str) -> str:
    out = _PATTERNS[0].sub(lambda m: f"{m.group(1)}{m.group(2)}{m.group(3)}[REDACTED]", text)
    for pat in _PATTERNS[1:]:
        out = pat.sub("[REDACTED]", out)
    return out


def digest(text: str) -> str:
    return "sha256:" + hashlib.sha256(text.encode("utf-8", "replace")).hexdigest()


def preview(text: str, limit: int = PREVIEW_CHARS) -> str:
    flat = " ".join(redact(text).split())
    return flat if len(flat) <= limit else flat[: limit - 1] + "…"
