#!/usr/bin/env python3
"""Sudo Supply agent guard: one hook script for Claude Code and Cursor. Stdlib only, Python 3.9+.

Blocks or asks before destructive commands (rm -rf, force-push, hard reset, DB drops,
mass rewrites, curl | sh) and stops agents reading secret files or writing secrets.

Modes (set by the hook config, see .claude/settings.json and .cursor/hooks.json):
  claude        Claude Code PreToolUse hook (Bash, Read, Edit, Write)
  cursor-shell  Cursor beforeShellExecution hook
  cursor-read   Cursor beforeReadFile hook
  cursor-write  Cursor preToolUse hook with matcher "Write"

Try it:  echo '{"tool_name":"Bash","tool_input":{"command":"git push --force"}}' | python3 .guardrails/guard.py claude

To customize, edit SHELL_RULES below. "deny" blocks outright; "ask" makes the tool prompt you.
Escape hatch: run the command yourself in your own terminal. Agents should not try to work around a block.
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from scan_secrets import is_sensitive_filename, scan_text  # noqa: E402

DENY, ASK = "deny", "ask"

# Command words like sudo, shred or bfg must stand alone, so a path such as
# C:\Users\me\sudo-supply\app or src/shred.ts is not mistaken for the command.
_W = r"(?<![\w.-])"  # not preceded by a word char, dot or hyphen
_E = r"(?![\w.-])"  # not followed by a word char, dot or hyphen

# (decision, pattern, reason). Patterns are matched against each sub-command
# (split on && || ; | and newlines) and against the full command text.
SHELL_RULES: list[tuple[str, str, str]] = [
    # --- deleting things
    # rm with -r and -f (combined, split, or long form) on /, ~, $HOME, ., .. or * (optionally quoted or followed by /*)
    (DENY, r"""\brm\s+(?=(?:-\S+\s+)*(?:-[a-zA-Z]*[rR]|--recursive\b))(?=(?:-\S+\s+)*(?:-[a-zA-Z]*f|--force\b))(?:\S+\s+)*["']?(/|/\*|~|~/|~/\*|\$HOME|\$\{HOME\}|\$HOME/|\$HOME/\*|\$\{HOME\}/|\$\{HOME\}/\*|\.|\./|\.\.|\.\./|\*|\./\*|\.\./\*)["']?(?=\s|$|[)'";`&|])""", "recursive force delete of /, ~, ., .. or *"),
    (DENY, r"\brm\s+.*--no-preserve-root", "rm --no-preserve-root"),
    (ASK, r"\brm\s+(-\S+\s+)*-[a-zA-Z]*[rR]", "recursive delete"),
    (ASK, r"\bfind\b.*\s(-delete|-exec\s+rm)\b", "bulk delete with find"),
    (DENY, _W + r"mkfs(\.\w+)?(?=\s+[^\s|;&])|" + _W + r"(wipefs|shred)" + _E + r"|\bdd\b.*\bof=/dev/", "disk-level destructive command"),
    (DENY, r"\bchmod\s+(-\S+\s+)*-R\s+0?777\b|\bchmod\s+0?777\s+-R\b", "recursive chmod 777"),
    # --- git history and work-in-progress
    (DENY, r"\bgit\s+(?:-[cC]\s+\S+\s+|--[\w-]+(?:=\S+)?\s+)*push\b.*(\s--force(?!-with-lease)\b|\s-[a-zA-Z]*f\b|\s\+\S+)", "force-push (rewrites remote history)"),
    (ASK, r"\bgit\s+(?:-[cC]\s+\S+\s+|--[\w-]+(?:=\S+)?\s+)*push\b.*--force-with-lease", "force-push with lease"),
    (ASK, r"\bgit\s+(?:-[cC]\s+\S+\s+|--[\w-]+(?:=\S+)?\s+)*push\b.*(\s--delete\b|\s-d\b|\s:\S+)", "deleting a remote branch or tag"),
    (ASK, r"\bgit\s+(?:-[cC]\s+\S+\s+|--[\w-]+(?:=\S+)?\s+)*push\b.*\b(main|master|production|prod|release)\b", "push to a protected branch"),
    (ASK, r"\bgit\s+reset\b.*--hard", "git reset --hard discards uncommitted work"),
    (ASK, r"\bgit\s+clean\b.*\s-[a-zA-Z]*f", "git clean -f deletes untracked files"),
    (ASK, r"\bgit\s+(checkout|restore)\b.*\s(--\s+)?\.(\s|$)", "discarding all local changes"),
    (ASK, r"\bgit\s+branch\b.*\s-D\b", "force-deleting a branch"),
    (ASK, r"\bgit\s+stash\s+(drop|clear)\b", "deleting stashed work"),
    (DENY, r"\bgit\s+(filter-branch|filter-repo)\b|" + _W + r"bfg(\.jar)?" + _E, "rewriting repository history"),
    (ASK, r"\bgit\s+(commit|push|merge|rebase)\b.*\s--no-verify\b", "skipping git hooks (--no-verify)"),
    (DENY, r"\bgit\s+add\b.*(\s|/)\.env(\s|$|\.(?!example|sample|template|dist))", "staging a .env file"),
    # --- databases and infrastructure
    (ASK, r"(?i)\b(drop\s+(database|schema|table)|truncate\s+(table\s+)?\w)", "dropping or truncating database objects"),
    (ASK, r"(?i)\bdelete\s+from\s+[\w.\"`]+\s*(;|$|\"|')", "DELETE without WHERE"),
    (ASK, _W + r"(dropdb|dropuser)" + _E + "|" + _W + r"(?i:flush(all|db))" + _E, "dropping a database or flushing a cache store"),
    (ASK, r"\b(prisma\s+migrate\s+reset|prisma\s+db\s+push\s+.*--force-reset|rails\s+db:(drop|reset)|rake\s+db:(drop|reset)|manage\.py\s+flush|alembic\s+downgrade\s+base)\b", "resetting a database"),
    (ASK, r"\b(terraform|tofu)\s+(destroy|apply\b.*-auto-approve)|\bpulumi\s+destroy\b", "destroying or auto-applying infrastructure"),
    (ASK, r"\bkubectl\s+delete\b|\bhelm\s+uninstall\b", "deleting cluster resources"),
    (ASK, r"\baws\s+s3\s+(rm|rb)\b.*--recursive|\baws\s+s3\s+rb\b|\bgsutil\s+(-m\s+)?rm\s+-r", "bulk-deleting cloud storage"),
    (ASK, r"\bdocker\s+(system|volume)\s+prune\b|\bdocker\s+volume\s+rm\b", "deleting Docker volumes/data"),
    # --- mass rewrites
    (ASK, r"\b(xargs|find)\b.*\bsed\s+(-\S+\s+)*-i|\bsed\s+-i\b.*\*\*", "in-place edit across many files"),
    (ASK, r"\b(xargs|find)\b.*\b(perl|ruby)\s+-[a-zA-Z]*i", "in-place edit across many files"),
    # --- remote code execution and leaks
    # curl/wget piped into a shell or interpreter, bash <(curl ...), and bash -c "$(curl ...)" (Homebrew-style)
    (DENY, r"""\b(curl|wget)\b[^|]*\|\s*(sudo\s+)?(-\S+\s+)*((ba|z|k|da)?sh\b|(python[\d.]*|node|perl|ruby|php)\b(?!\s+(-[a-zA-Z]*[cemEp]\b|--eval\b|--print\b)))|\b((ba|z|k|da)?sh|python[\d.]*|node|perl|ruby)\s+<\s*\(\s*(curl|wget)|\b(ba|z|k|da)?sh\s+(-\S+\s+)*-c\s+["']?\$\(\s*(curl|wget)\b""", "piping a remote script into a shell"),
    (ASK, _W + "sudo" + _E, "running as root"),
    (ASK, r"(^|\s)(printenv|env)\s*($|\|)|\bset\s*\|", "dumping all environment variables"),
    (ASK, r"\b(cat|less|more|head|tail|bat|type|nl|xxd|strings|cp|scp|base64)\b[^|;&]*(^|[\s/])\.env(\.(?!example|sample|template|dist)\w+)?(\s|$)", "reading a .env file"),
    (ASK, r"\b(cat|less|more|head|tail|cp|scp|base64)\b.*(id_rsa|id_ed25519|\.pem\b|\.p12\b|\.aws/credentials|\.npmrc|\.netrc|\.pgpass)", "reading a key or credentials file"),
    (ASK, r"\becho\b.*\$\{?\w*(SECRET|TOKEN|PASSWORD|PASSWD|API_KEY|PRIVATE_KEY)\w*", "printing a secret variable"),
    (ASK, r"\b(npm|pnpm|yarn)\s+publish\b|\btwine\s+upload\b|\bcargo\s+publish\b|\bgh\s+release\s+create\b", "publishing a package or release"),
]
_COMPILED: list | None = None


def compiled_rules() -> list:
    global _COMPILED
    if _COMPILED is None:
        _COMPILED = [(d, re.compile(p), r) for d, p, r in SHELL_RULES]
    return _COMPILED
SPLIT = re.compile(r"&&|\|\||;|\n|(?<!\|)\|(?!\|)")


def check_command(command: str) -> tuple[str, str] | None:
    """Return (decision, reason) for the strictest matching rule, or None."""
    parts = [command] + [p.strip() for p in SPLIT.split(command) if p.strip()]
    hit: tuple[str, str] | None = None
    for decision, rx, reason in compiled_rules():
        if any(rx.search(p) for p in parts):
            if decision == DENY:
                return decision, reason
            hit = hit or (decision, reason)
    return hit


def check_read(path: str) -> tuple[str, str] | None:
    if path and is_sensitive_filename(path):
        return DENY, f"reading secret file {Path(path.replace(chr(92), '/')).name}"
    return None


def check_content(texts: list[str]) -> tuple[str, str] | None:
    for t in texts:
        found = scan_text(t)
        if found:
            return DENY, f"content looks like it contains a secret ({found[0][1]}); use an env var or secret manager instead"
    return None


def strings_in(obj) -> list[str]:
    if isinstance(obj, str):
        return [obj]
    if isinstance(obj, dict):
        return [s for v in obj.values() for s in strings_in(v)]
    if isinstance(obj, list):
        return [s for v in obj for s in strings_in(v)]
    return []


def message(reason: str) -> str:
    return (
        f"Blocked by Sudo Supply guardrails: {reason}. "
        "Do not try to work around this. Explain what you wanted to do and why, and let the user run it themselves if it is really needed."
    )


def run_claude(payload: dict) -> int:
    tool = payload.get("tool_name", "")
    ti = payload.get("tool_input") or {}
    result = None
    if tool == "Bash":
        result = check_command(ti.get("command", ""))
    elif tool in ("Read", "Edit", "Write", "MultiEdit"):
        result = check_read(ti.get("file_path", ""))
        if result is None and tool != "Read":
            texts = [ti.get("content", ""), ti.get("new_string", "")]
            texts += [e.get("new_string", "") for e in ti.get("edits", []) if isinstance(e, dict)]
            result = check_content([t for t in texts if t])
    if result is None:
        return 0  # no decision: normal permission flow applies
    decision, reason = result
    print(json.dumps({"hookSpecificOutput": {
        "hookEventName": "PreToolUse",
        "permissionDecision": decision,
        "permissionDecisionReason": message(reason) if decision == DENY else f"Sudo Supply guardrails: {reason}. Approve only if you intended this.",
    }}))
    return 0


def run_cursor(mode: str, payload: dict) -> int:
    if mode == "cursor-shell":
        result = check_command(payload.get("command", ""))
    elif mode == "cursor-read":
        result = check_read(payload.get("file_path", ""))
    else:  # cursor-write: preToolUse for Write; scan every string in tool_input
        ti = payload.get("tool_input") or {}
        path = ti.get("file_path") or ti.get("path") or ""
        result = check_read(path) or check_content(strings_in(ti))
        if result and result[0] == ASK:  # preToolUse does not enforce "ask"
            result = (DENY, result[1])
    if result is None:
        out = {"permission": "allow"}
    else:
        decision, reason = result
        out = {
            "permission": decision,
            "user_message": f"Sudo Supply guardrails: {reason}.",
            "agent_message": message(reason) if decision == DENY else f"This needs the user's approval: {reason}.",
        }
        if mode == "cursor-read":  # beforeReadFile's documented output is only permission + user_message
            del out["agent_message"]
    print(json.dumps(out))
    return 0


def main(argv: list[str]) -> int:
    mode = argv[0] if argv else ""
    try:
        payload = json.loads(sys.stdin.read() or "{}")
    except json.JSONDecodeError:
        print("guard.py: invalid JSON on stdin", file=sys.stderr)
        return 2  # block when input can't be understood
    if mode == "claude":
        return run_claude(payload)
    if mode in ("cursor-shell", "cursor-read", "cursor-write"):
        return run_cursor(mode, payload)
    print(__doc__, file=sys.stderr)
    return 1


if __name__ == "__main__":
    try:
        sys.exit(main(sys.argv[1:]))
    except Exception as exc:  # a broken guard must block, not silently allow
        print(f"guard.py crashed ({type(exc).__name__}: {exc}); blocking. Fix .guardrails/guard.py.", file=sys.stderr)
        sys.exit(2)
