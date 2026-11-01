#!/usr/bin/env python3
"""Sudo Supply secret scanner. Stdlib only, Python 3.9+.

Usage:
  python3 .guardrails/scan_secrets.py --staged        # scan staged changes (pre-commit)
  python3 .guardrails/scan_secrets.py PATH [PATH...]  # scan files or directories
  python3 .guardrails/scan_secrets.py --stdin         # scan text from stdin

Exit codes: 0 = clean, 1 = possible secrets found, 2 = usage error.
Findings print file:line and the rule name. Secret values are never printed.
Suppress a false positive by adding `guardrails:allow` on the same line.
"""
from __future__ import annotations

import os
import re
import subprocess
import sys
from pathlib import Path

# name -> regex. Keep these specific: noisy scanners get disabled.
RULES: dict[str, re.Pattern[str]] = {
    "private-key": re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----"),
    "aws-access-key-id": re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
    "github-token": re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,}\b|\bgithub_pat_[A-Za-z0-9_]{60,}\b"),
    "gitlab-token": re.compile(r"\bglpat-[A-Za-z0-9_-]{20,}\b"),
    "slack-token": re.compile(r"\bxox[abposr]-[A-Za-z0-9-]{10,}\b"),
    "slack-webhook": re.compile(r"https://hooks\.slack\.com/services/[A-Za-z0-9/]{20,}"),
    "stripe-live-key": re.compile(r"\b(?:sk|rk)_live_[A-Za-z0-9]{20,}\b"),
    "google-api-key": re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b"),
    "openai-key": re.compile(r"\bsk-(?:proj-|svcacct-|admin-)?[A-Za-z0-9_-]{32,}\b"),
    "anthropic-key": re.compile(r"\bsk-ant-[A-Za-z0-9_-]{32,}\b"),
    "npm-token": re.compile(r"\bnpm_[A-Za-z0-9]{36}\b"),
    "jwt": re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"),
    "url-with-password": re.compile(r"\b[a-z][a-z0-9+.-]*://[^\s:/@]+:[^\s@/]{6,}@[^\s/]+", re.I),
    "assigned-secret": re.compile(
        r"""(?ix)\b[\w.-]*(?:secret|passw(?:or)?d|api[_-]?key|access[_-]?key|auth[_-]?token|private[_-]?key|client[_-]?secret)[\w.-]*
            \s*[:=]\s*["']([^"'\s]{12,})["']"""
    ),
}
PLACEHOLDER = re.compile(r"(?i)(example|placeholder|changeme|change_me|your[_-]|dummy|redacted|xxxx|<[^>]+>|\$\{|\{\{|process\.env|os\.environ|getenv|:(password|pass|secret|postgres|root)@|@(localhost|127\.0\.0\.1|0\.0\.0\.0|db|postgres|mysql|redis)\b)")
ALLOW_MARK = "guardrails:allow"
SKIP_DIRS = {".git", "node_modules", ".venv", "venv", "__pycache__", ".next", "dist", "build", "vendor", ".tox"}
SKIP_SUFFIXES = {".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico", ".pdf", ".zip", ".gz", ".woff", ".woff2", ".ttf", ".lock"}
MAX_BYTES = 1_000_000


def scan_text(text: str) -> list[tuple[int, str]]:
    """Return (line_number, rule_name) for each suspected secret."""
    findings: list[tuple[int, str]] = []
    for lineno, line in enumerate(text.splitlines(), 1):
        if ALLOW_MARK in line:
            continue
        for name, rx in RULES.items():
            m = rx.search(line)
            if not m:
                continue
            value = m.group(1) if m.groups() else m.group(0)
            if name in ("assigned-secret", "url-with-password") and PLACEHOLDER.search(value or line):
                continue
            findings.append((lineno, name))
            break
    return findings


def is_sensitive_filename(path: str) -> bool:
    """Files that should never be committed or read by an agent."""
    name = os.path.basename(path.replace("\\", "/"))
    if name in {".env.example", ".env.sample", ".env.template", ".env.dist"}:
        return False
    return bool(
        name == ".env"
        or name.startswith(".env.")
        or re.search(r"\.(pem|key|p12|pfx|jks|keystore)$", name)
        or name in {"id_rsa", "id_dsa", "id_ecdsa", "id_ed25519", ".netrc", ".pgpass", "credentials", "credentials.json", "secrets.json", "service-account.json"}
    )


def iter_files(paths: list[str]):
    for p in paths:
        path = Path(p)
        if path.is_dir():
            for root, dirs, files in os.walk(path):
                dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
                for f in files:
                    yield Path(root) / f
        elif path.is_file():
            yield path


def read_text(path: Path) -> str | None:
    if path.suffix.lower() in SKIP_SUFFIXES:
        return None
    try:
        if path.stat().st_size > MAX_BYTES:
            return None
        data = path.read_bytes()
    except OSError:
        return None
    if b"\0" in data[:4096]:
        return None
    return data.decode("utf-8", errors="replace")


def staged() -> list[tuple[str, str]]:
    """(path, added_text) for staged changes. Only added lines are scanned."""
    names = subprocess.run(
        ["git", "diff", "--cached", "--name-only", "--diff-filter=ACMR"],
        capture_output=True, text=True, check=True,
    ).stdout.split("\n")
    out = []
    for name in filter(None, names):
        diff = subprocess.run(
            ["git", "diff", "--cached", "-U0", "--no-color", "--", name],
            capture_output=True, text=True, errors="replace", check=True,
        ).stdout
        added = "\n".join(l[1:] for l in diff.splitlines() if l.startswith("+") and not l.startswith("+++"))
        out.append((name, added))
    return out


def main(argv: list[str]) -> int:
    if not argv or argv[0] in ("-h", "--help"):
        print(__doc__)
        return 2
    problems: list[str] = []
    if argv[0] == "--stdin":
        problems += [f"<stdin>:{n}: {rule}" for n, rule in scan_text(sys.stdin.read())]
    elif argv[0] == "--staged":
        for name, added in staged():
            if is_sensitive_filename(name):
                problems.append(f"{name}: sensitive file staged (should be gitignored)")
            # line numbers refer to the added hunk, not the file
            problems += [f"{name}: added line {n}: {rule}" for n, rule in scan_text(added)]
    else:
        for path in iter_files(argv):
            text = read_text(path)
            if text is not None:
                problems += [f"{path}:{n}: {rule}" for n, rule in scan_text(text)]
    if problems:
        print("Possible secrets found (values not shown):", file=sys.stderr)
        for p in problems:
            print(f"  {p}", file=sys.stderr)
        print(f"Move secrets to env vars / a secret manager. False positive? add '{ALLOW_MARK}' on that line.", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
