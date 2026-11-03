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
import shlex
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
    (ASK, r"\bgit\s+(?:-[cC]\s+\S+\s+|--[\w-]+(?:=\S+)?\s+)*push\b.*\s--mirror\b", "mirror push (overwrites every remote branch)"),
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
    (ASK, r"\b(cat|less|more|head|tail|bat|type|nl|xxd|strings|cp|scp|base64|grep|egrep|fgrep|rg|awk|sed|sort|uniq|od|hexdump|tac|rev|cut|paste|diff|column)\b[^|;&]*(^|[\s/])\.env(\.(?!example|sample|template|dist)\w+)?(\s|$)", "reading a .env file"),
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


def check_raw(command: str) -> tuple[str, str] | None:
    """Return (decision, reason) for the strictest rule matching the text as written, or None."""
    parts = [command] + [p.strip() for p in SPLIT.split(command) if p.strip()]
    hit: tuple[str, str] | None = None
    for decision, rx, reason in compiled_rules():
        if any(rx.search(p) for p in parts):
            if decision == DENY:
                return decision, reason
            hit = hit or (decision, reason)
    return hit


def check_command(command: str) -> tuple[str, str] | None:
    """Return (decision, reason) for the strictest matching rule, or None.

    Checks the command as written, then what it really runs (see check_nested). A crash in the
    nested analysis blocks rather than passing.
    """
    hit = check_raw(command)
    if hit and hit[0] == DENY:
        return hit
    try:
        nested = check_nested(command)
    except Exception as exc:  # fail closed
        return DENY, f"guard couldn't analyse this command ({type(exc).__name__}); blocking to be safe"
    if nested and (nested[0] == DENY or hit is None):
        return nested
    return hit


# --- nested and wrapped commands ------------------------------------------------------------
# The rules above are also run on what a command would really execute: the payload of
# sh/bash/zsh -c, eval, $(...) and backticks, xargs and find -exec, sudo/env/nohup/timeout
# and similar prefixes, aliases and variables set in the same command, python -c / node -e /
# perl -e / ruby -e code, and anything piped or here-string'd into a shell. Quotes and
# backslashes are removed first, so 'rm', r\m and "r""m" all read as rm.
# Fail closed: nesting deeper than MAX_DEPTH, too many derived commands, or a payload that
# can't be parsed (unbalanced quotes) blocks instead of passing.
MAX_DEPTH = 5
MAX_DERIVED = 300

_SHELLS = {"sh", "bash", "zsh", "dash", "ksh", "mksh", "ash", "fish", "yash", "posh"}
_SU = {"su", "runuser"}
_INTERPRETERS = {"python", "node", "nodejs", "bun", "deno", "perl", "ruby", "php"}
_KEYWORDS = {"if", "then", "else", "elif", "do", "while", "until", "!", "time", "{", "fi", "done", "}"}
_DECLARE = {"export", "local", "readonly", "declare", "typeset"}
# wrapper -> options that take a separate value, number of positionals to skip before the command
_WRAPPERS: dict[str, tuple[frozenset, int]] = {
    "sudo": (frozenset("-u -g -h -p -C -D -r -t -U -T --user --group --host --prompt --chdir --role --type --other-user --close-from".split()), 0),
    "doas": (frozenset({"-u", "-C"}), 0),
    "env": (frozenset({"-u", "-C", "--unset", "--chdir", "-S", "--split-string"}), 0),
    "nohup": (frozenset(), 0), "time": (frozenset({"-f", "-o"}), 0), "builtin": (frozenset(), 0),
    "command": (frozenset(), 0), "exec": (frozenset({"-a"}), 0), "nice": (frozenset({"-n", "--adjustment"}), 0),
    "ionice": (frozenset({"-c", "-n", "-p", "-P", "-u"}), 0), "timeout": (frozenset({"-s", "-k", "--signal", "--kill-after"}), 1),
    "stdbuf": (frozenset({"-i", "-o", "-e"}), 0), "setsid": (frozenset(), 0), "unbuffer": (frozenset(), 0),
    "chrt": (frozenset(), 1), "taskset": (frozenset(), 1), "busybox": (frozenset(), 0), "caffeinate": (frozenset({"-t", "-w"}), 0),
    "flock": (frozenset({"-w", "-E", "--timeout", "--conflict-exit-code"}), 1),
}
_PLACEHOLDER = "__guard_subst_{}__"
_PH_RX = re.compile(r"__guard_subst_(plain|decode|fetch)__")
_DECODER = re.compile(r"\bbase64\b[^|;&]*\s(-d|--decode|-D)\b|\bxxd\b[^|;&]*\s-r|\bopenssl\b[^|;&]*\s-d\b|\buudecode\b|\bbase32\b[^|;&]*\s(-d|--decode)\b")
_FETCH = re.compile(r"\b(curl|wget|fetch|aria2c)\b")
_TRIGGERS = re.compile(r"\$\(|`|<\(|\b(eval|exec|xargs|find|base64|xxd|curl|wget|sh|bash|zsh|dash|ksh|fish|su|sudo|doas|env|python[\d.]*|node|perl|ruby|php|rm|git|alias)\b")
_ASSIGN = re.compile(r"^([A-Za-z_]\w*)\+?=(.*)$", re.S)
_VAR = re.compile(r"\$(?:\{([A-Za-z_]\w*)\}|([A-Za-z_]\w*))")
_HEREDOC = re.compile(r"(?<!<)<<(-?)[ \t]*(['\"]?)([A-Za-z_][\w.-]*)\2")
_FIND_NONFILTER = {"-exec", "-execdir", "-ok", "-okdir", "-delete", "-depth", "-xdev", "-mount", "-print", "-print0",
                   "-follow", "-noleaf", "-ignore_readdir_race", "-daystart", "-L", "-H", "-P", "-d"}

# Recursive deletes and .env reads written in python/node/perl/ruby code.
_ROOTISH = (r"""(?:(['"])(?:/|/\*|~|~/|\.|\./|\.\.|\$HOME|\$\{HOME\})\1|os\.path\.expanduser\(\s*(['"])~/?\2\s*\)"""
            r"""|(?:pathlib\.)?Path\.home\(\)|Path\(\s*(['"])(?:/|~|\.)\3\s*\)|os\.environ\[\s*(['"])HOME\4\s*\]"""
            r"""|os\.(?:environ\.get|getenv)\(\s*(['"])HOME\5\s*\)|process\.env\.HOME|os\.homedir\(\)|homedir\(\)"""
            r"""|ENV\[\s*(['"])HOME\6\s*\]|\$ENV\{HOME\}|Dir\.home)""")
_RDEL = (r"(?:\bshutil\.rmtree|\brmtree|\bremove_tree|\brm_rf|\brm_r|\brmSync|\brmdirSync|\bfs\.rm|\bfs\.promises\.rm"
         r"|\brimraf(?:\.sync)?|\bFileUtils\.(?:rm_rf|remove_dir|rm_r|remove_entry))\s*\(\s*")
_INTERP_RULES = [
    (DENY, re.compile(_RDEL + _ROOTISH), "recursive delete of /, ~ or . from a script"),
    (ASK, re.compile(_RDEL), "recursive delete from a script"),
    (ASK, re.compile(r"""\b(?:open|read_text|read_bytes|readFileSync|readFile|File\.read|IO\.read|file_get_contents|Path|slurp)\s*\(\s*(['"])(?:[^'"]*/)?\.env(?:\.(?!example|sample|template|dist)\w+)?\1"""), "reading a .env file"),
]
_STR_LIT = re.compile(r"""'((?:[^'\\]|\\.)*)'|"((?:[^"\\]|\\.)*)"|`([^`]*)`""")
_LIST_LIT = re.compile(r"""\[\s*((?:(?:'[^']*'|"[^"]*")\s*,\s*)+(?:'[^']*'|"[^"]*"))\s*,?\s*\]""")


class _Stop(Exception):
    pass


class _State:
    def __init__(self) -> None:
        self.hit: tuple[str, str] | None = None
        self.count = 0
        self.vars: dict[str, str] = {}
        self.computed: set[str] = set()
        self.aliases: dict[str, str] = {}

    def add(self, result) -> None:
        if not result:
            return
        if result[0] == DENY:
            self.hit = result
            raise _Stop
        self.hit = self.hit or result


def _match_rules(text: str):
    if not text.strip():
        return None
    return check_raw(text)


def _strip_heredocs(text: str) -> tuple[str, list[tuple[str, str]]]:
    """Remove heredoc bodies. Returns the text and [(head of the command that reads it, body)]."""
    lines = text.split("\n")
    out, docs, i = [], [], 0
    while i < len(lines):
        line = lines[i]
        out.append(line)
        i += 1
        for m in _HEREDOC.finditer(line):
            dash, delim = m.group(1), m.group(3)
            for j in range(i, len(lines)):
                cand = lines[j].lstrip("\t") if dash else lines[j]
                if cand.rstrip() == delim:
                    seg = re.split(r"\$\(|&&|\|\||[;&|(`]", line[: m.start()])[-1].split()
                    while seg and (seg[0] in _WRAPPERS or _ASSIGN.match(seg[0]) or seg[0].startswith("-")):
                        seg = seg[1:]
                    docs.append((_base(seg[0]) if seg else "", "\n".join(lines[i:j])))
                    i = j + 1
                    out.append(delim)
                    break
    return "\n".join(out), docs


def _match_close(text: str, i: int, closer: str) -> int:
    """Index just past the closer matching an opener that ends at i (quote-aware); len(text) if none."""
    depth, n, state = 1, len(text), ""
    while i < n:
        c = text[i]
        if state == "'":
            if c == "'":
                state = ""
        elif c == "\\":
            i += 1
        elif state == '"':
            if c == '"':
                state = ""
            elif closer == "`" and c == "`":
                return i + 1
        elif c in "'\"":
            state = c
        elif closer == "`":
            if c == "`":
                return i + 1
        elif c == "(":
            depth += 1
        elif c == ")":
            depth -= 1
            if depth == 0:
                return i + 1
        i += 1
    return n


def _simulate(body: str) -> str | None:
    """Output of a substitution that is only `echo words` or `printf words`, else None."""
    if re.search(r"[|;&<>`]|\$\(", body):
        return None
    try:
        w = shlex.split(body)
    except ValueError:
        return None
    if not w or w[0] not in ("echo", "printf"):
        return None
    args = [a for a in w[1:] if not re.fullmatch(r"-[neE]+", a)] if w[0] == "echo" else w[1:]
    if w[0] == "printf" and args and "%" in args[0]:
        args = args[1:]
    return " ".join(args)


def _flatten(text: str) -> tuple[str, list[str]]:
    """Drop comments and replace $(...), backticks and <(...) with their echo output or a placeholder."""
    out, bodies, i, n, state = [], [], 0, len(text), ""
    while i < n:
        c = text[i]
        if state == "'":
            out.append(c)
            state = "" if c == "'" else state
            i += 1
            continue
        if c == "\\":
            out.append(text[i : i + 2])
            i += 2
            continue
        start_sub = text.startswith("$(", i) or c == "`" or (state == "" and text[i : i + 2] in ("<(", ">("))
        if start_sub:
            closer = "`" if c == "`" else ")"
            begin = i + 1 if c == "`" else i + 2
            end = _match_close(text, begin, closer)
            body = text[begin : end - 1] if end <= n and text[end - 1 : end] == closer else text[begin:end]
            bodies.append(body)
            sim = _simulate(body) if text[i] in "$`" else None
            if sim is not None:
                out.append(sim)
            else:
                kind = "decode" if _DECODER.search(body) else "fetch" if _FETCH.search(body) else "plain"
                out.append(_PLACEHOLDER.format(kind))
            i = end
            continue
        if state == '"':
            state = "" if c == '"' else state
        elif c in "'\"":
            state = c
        elif c == "#" and (i == 0 or text[i - 1] in " \t\n;&|()"):
            while i < n and text[i] != "\n":
                i += 1
            continue
        out.append(c)
        i += 1
    return "".join(out), bodies


def _tokenize(text: str) -> list[str]:
    lex = shlex.shlex(text, posix=True, punctuation_chars="();<>|&\n")
    lex.whitespace = " \t\r"
    lex.whitespace_split = True
    lex.commenters = ""
    return list(lex)


def _commands(tokens: list[str]) -> list[dict]:
    """Split tokens into simple commands: {"words", "redirs": [(op, target)], "piped": fed by a pipe}."""
    cmds, cur, piped, i = [], {"words": [], "redirs": [], "piped": False}, False, 0
    while i < len(tokens):
        t = tokens[i]
        if t and all(ch in "();<>|&\n" for ch in t):
            if "<" in t or ">" in t:
                target = tokens[i + 1] if i + 1 < len(tokens) else ""
                cur["redirs"].append((t.strip("();|\n"), target))
                i += 2
                continue
            if cur["words"] or cur["redirs"]:
                cmds.append(cur)
            piped = bool(re.fullmatch(r"\)*\|&?", t))
            cur = {"words": [], "redirs": [], "piped": piped}
            i += 1
            continue
        cur["words"].append(t)
        i += 1
    if cur["words"] or cur["redirs"]:
        cmds.append(cur)
    return cmds


def _base(word: str) -> str:
    b = word.replace("\\", "/").rsplit("/", 1)[-1]
    m = re.fullmatch(r"(python|pypy)[\d.]*|(node)js|(perl)[\d.]*|(ruby)[\d.]*|(php)[\d.]*", b)
    if m:
        return next(g for g in m.groups() if g) if not b.startswith("pypy") else "python"
    return b[:-4] if b.lower().endswith(".exe") else b


def _unwrap(words: list[str]) -> tuple[list[str], list[str]]:
    """Strip prefixes like sudo, env VAR=x, nohup, timeout 5. Returns (inner words, env -S payloads)."""
    payloads: list[str] = []
    for _ in range(20):
        if not words:
            break
        head = _base(words[0])
        if head in ("command", "builtin") and len(words) > 1 and words[1] in ("-v", "-V"):
            return [], payloads  # a lookup, not a run
        if head not in _WRAPPERS:
            break
        takes, skip = _WRAPPERS[head]
        i = 1
        while i < len(words):
            w = words[i]
            if w == "--":
                i += 1
                break
            if head in ("env", "sudo") and _ASSIGN.match(w):
                i += 1
                continue
            if w.startswith("-") and len(w) > 1:
                if w in ("-S", "--split-string") and head == "env" and i + 1 < len(words):
                    payloads.append(words[i + 1])
                if w in takes:
                    i += 2
                    continue
                if head == "env" and w.startswith("-S") and len(w) > 2:
                    payloads.append(w[2:])
                i += 1
                continue
            break
        i += skip
        words = words[i:]
    return words, payloads


def _shell_payload(words: list[str]) -> tuple[str | None, bool]:
    """(the -c payload, reads its script from stdin) for sh/bash/zsh/su words."""
    head = _base(words[0])
    args = words[1:]
    if head in _SU:
        for k, a in enumerate(args):
            if a in ("-c", "--command") and k + 1 < len(args):
                return args[k + 1], False
            if a.startswith("--command="):
                return a.split("=", 1)[1], False
        return None, False
    has_c, k = False, 0
    while k < len(args):
        a = args[k]
        if a in ("-o", "+o", "-O", "+O", "--rcfile", "--init-file"):
            k += 2
            continue
        if a == "--" or a == "-":
            k += 1
            break
        if a.startswith("--"):
            k += 1
            continue
        if re.fullmatch(r"[-+][A-Za-z]+", a):
            has_c = has_c or "c" in a[1:]
            k += 1
            continue
        break
    rest = args[k:]
    if has_c:
        return (rest[0] if rest else ""), False
    return None, not rest


def _interp_code(words: list[str]) -> tuple[list[str], bool]:
    """(code strings given with -c/-e/-r/eval, reads its program from stdin) for an interpreter."""
    head, args, code = _base(words[0]), words[1:], []
    k = 0
    if head == "deno" and args and args[0] == "eval":
        return args[1:2], False
    while k < len(args):
        a = args[k]
        flag = (head == "python" and re.fullmatch(r"-[A-Za-z]*c", a)) or \
               (head in ("node", "bun") and a in ("-e", "--eval", "-p", "--print")) or \
               (head in ("perl", "ruby") and re.fullmatch(r"-[a-zA-Z]*[eE]", a) and a[1] not in "MImr") or \
               (head == "php" and a == "-r")
        if flag and k + 1 < len(args):
            code.append(args[k + 1])
            k += 2
            if head == "python":
                break
            continue
        if head == "python" and a in ("-m",):
            return code, False
        if a.startswith("-") and a != "-":
            k += 1
            continue
        return code, (a == "-" and not code)
    return code, not code


def _payload_hit(st: _State, payload: str, what: str) -> None:
    for kind in _PH_RX.findall(payload):
        if kind == "decode":
            st.add((DENY, f"{what} runs a decoded (base64/hex) payload"))
        elif kind == "fetch":
            st.add((DENY, f"{what} runs a downloaded script"))
        else:
            st.add((ASK, f"{what} runs a command computed at run time"))


def _analyse_interp(code: str, depth: int, st: _State) -> None:
    if depth > MAX_DEPTH:
        st.add((DENY, f"command nested more than {MAX_DEPTH} levels deep; too deep to check"))
    for decision, rx, reason in _INTERP_RULES:
        if rx.search(code):
            st.add((decision, reason))
    for m in _LIST_LIT.finditer(code):
        parts = re.findall(r"""'([^']*)'|"([^"]*)\"""", m.group(1))
        _analyse(shlex.join(a or b for a, b in parts), depth + 1, st, strict=False)
    for m in _STR_LIT.finditer(code):
        lit = next((g for g in m.groups() if g is not None), "")
        if re.search(r"\s", lit):
            _analyse(lit, depth + 1, st, strict=False)


def _analyse(text: str, depth: int, st: _State, strict: bool = True) -> None:
    st.count += 1
    if st.count > MAX_DERIVED:
        st.add((DENY, "too many nested commands to check"))
    if depth > MAX_DEPTH:
        st.add((DENY, f"command nested more than {MAX_DEPTH} levels deep; too deep to check"))
    if depth > 0:
        st.add(_match_rules(text))
    text, docs = _strip_heredocs(text)
    for head, body in docs:
        if head in _SHELLS:
            _analyse(body, depth + 1, st)
        elif head in _INTERPRETERS:
            _analyse_interp(body, depth + 1, st)
    flat, bodies = _flatten(text)
    for body in bodies:
        _analyse(body, depth + 1, st, strict)
    try:
        tokens = _tokenize(flat)
    except ValueError:
        if strict and _TRIGGERS.search(text):
            st.add((DENY, "couldn't parse this command (unbalanced quotes) to check what it runs"))
        return
    st.add(_match_rules(" ".join(t if t.strip() else ";" for t in tokens)))
    cmds = _commands(tokens)
    for idx, cmd in enumerate(cmds):
        k = idx
        while k > 0 and cmds[k]["piped"]:
            k -= 1
        _analyse_simple(cmd, cmds[k:idx], depth, st)


def _analyse_simple(cmd: dict, producers: list[dict], depth: int, st: _State) -> None:
    words = list(cmd["words"])
    for op, target in cmd["redirs"]:
        if op.endswith("<") and not op.endswith("<<") and target:
            st.add(_match_rules("cat " + target))
    while words and (words[0] in _KEYWORDS or words[0] in _DECLARE or _ASSIGN.match(words[0])):
        m = _ASSIGN.match(words[0])
        if m:
            st.vars[m.group(1)] = m.group(2)
            if _PH_RX.search(m.group(2)):
                st.computed.add(m.group(1))
        words = words[1:]
    if not words:
        return
    if words[0] == "alias":
        for a in words[1:]:
            m = _ASSIGN.match(a)
            if m:
                st.aliases[m.group(1)] = m.group(2)
        return
    if any("$" in w for w in words):
        new = [_VAR.sub(lambda m: st.vars.get(m.group(1) or m.group(2), m.group(0)), w) for w in words]
        if new != words:
            words = new[0].split() + new[1:] if new[0] != words[0] else new
            st.add(_match_rules(" ".join(words)))
    if words and words[0] in st.aliases:
        try:
            words = shlex.split(st.aliases.pop(words[0])) + words[1:]
        except ValueError:
            st.add((DENY, "couldn't parse an alias defined in this command"))
        st.add(_match_rules(" ".join(words)))
    inner, payloads = _unwrap(words)
    for p in payloads:
        _analyse(p, depth + 1, st)
    if inner != words:
        st.add(_match_rules(" ".join(inner)))
    words = inner
    if not words:
        return
    head = _base(words[0])
    m = _VAR.fullmatch(words[0])
    if _PH_RX.search(words[0]) or (m and (m.group(1) or m.group(2)) in st.computed):
        _payload_hit(st, words[0] if _PH_RX.search(words[0]) else _PLACEHOLDER.format("plain"), "the command name is computed at run time;")
    reads_stdin = False
    if head in _SHELLS or head in _SU:
        payload, reads_stdin = _shell_payload(words)
        if payload is not None:
            _payload_hit(st, payload, f"{head} -c")
            _analyse(payload, depth + 1, st)
        for op, target in cmd["redirs"]:
            if op == "<<<":
                _payload_hit(st, target, f"{head} <<<")
                _analyse(target, depth + 1, st)
    elif head == "eval":
        payload = " ".join(words[1:])
        _payload_hit(st, payload, "eval")
        _analyse(payload, depth + 1, st)
    elif head in _INTERPRETERS:
        code, reads_stdin = _interp_code(words)
        for c in code:
            _analyse_interp(c, depth + 1, st)
        for op, target in cmd["redirs"]:
            if op == "<<<":
                _analyse_interp(target, depth + 1, st)
    elif head == "xargs":
        _analyse_xargs(words, producers, depth, st)
    elif head == "find":
        _analyse_find(words, depth, st)
    elif head == "git":
        _analyse_git(words, depth, st)
    elif head == "watch":
        rest = [w for w in words[1:] if not w.startswith("-")]
        if rest:
            _analyse(" ".join(rest), depth + 1, st)
    if reads_stdin and producers:
        for p in producers:
            pt = " ".join(p["words"])
            if _DECODER.search(pt):
                st.add((DENY, f"decoding a hidden (base64/hex) script into {head}"))
            if _FETCH.search(pt):
                st.add((DENY, "piping a remote script into a shell"))
        last = producers[-1]["words"]
        if last and last[0] in ("echo", "printf"):
            body = _simulate(shlex.join(last)) or ""
            if head in _INTERPRETERS:
                _analyse_interp(body, depth + 1, st)
            else:
                _analyse(body, depth + 1, st)


def _analyse_xargs(words: list[str], producers: list[dict], depth: int, st: _State) -> None:
    takes = {"-I", "-n", "-P", "-L", "-l", "-d", "-E", "-e", "-s", "-a", "--max-args", "--max-procs",
             "--delimiter", "--arg-file", "--replace", "--max-lines", "--eof", "--max-chars"}
    i, repl = 1, None
    while i < len(words) and words[i].startswith("-"):
        w = words[i]
        if w == "--":
            i += 1
            break
        if w in ("-I", "--replace"):
            repl = words[i + 1] if i + 1 < len(words) else None
        elif w.startswith("-I") or w.startswith("-i"):
            repl = w[2:] or "{}"
        elif w.startswith("--replace="):
            repl = w.split("=", 1)[1]
        i += 2 if w in takes else 1
    rest = words[i:]
    if not rest:
        return
    feed: list[str] = []
    if producers and producers[-1]["words"] and producers[-1]["words"][0] in ("echo", "printf"):
        feed = (_simulate(shlex.join(producers[-1]["words"])) or "").split()
    if feed:
        rest = [w.replace(repl, " ".join(feed)) for w in rest] if repl else rest + feed
    _analyse(shlex.join(rest), depth + 1, st)
    st.add(_match_rules(" ".join(rest)))


def _analyse_find(words: list[str], depth: int, st: _State) -> None:
    args = words[1:]
    while args and args[0] in ("-H", "-L", "-P"):
        args = args[1:]
    starts = []
    while args and not args[0].startswith("-") and args[0] not in ("(", "!", ","):
        starts.append(args.pop(0))
    starts = starts or ["."]
    preds, k = [], 0
    while k < len(args):  # predicates outside -exec ... ; chunks
        if args[k] in ("-exec", "-execdir", "-ok", "-okdir"):
            while k < len(args) and args[k] not in (";", "+"):
                k += 1
        else:
            preds.append(args[k])
        k += 1
    filtered = any((a.startswith("-") and a not in _FIND_NONFILTER) or a in ("(", "!") for a in preds)
    i = 0
    while i < len(args):
        if args[i] in ("-exec", "-execdir", "-ok", "-okdir"):
            j = i + 1
            while j < len(args) and args[j] not in (";", "+"):
                j += 1
            chunk = args[i + 1 : j]
            if chunk:
                if not filtered:
                    for s in starts:
                        sub = [w.replace("{}", s) for w in chunk]
                        _analyse(shlex.join(sub), depth + 1, st)
                        st.add(_match_rules(" ".join(sub)))
                else:
                    _analyse(shlex.join(chunk), depth + 1, st)
            i = j + 1
            continue
        if args[i] == "-delete" and not filtered:
            for s in starts:
                st.add(_match_rules(f"rm -rf {s}"))
        i += 1


def _analyse_git(words: list[str], depth: int, st: _State) -> None:
    aliases, i = {}, 1
    while i < len(words) and words[i].startswith("-"):
        if words[i] == "-c" and i + 1 < len(words):
            key, _, val = words[i + 1].partition("=")
            if key.lower().startswith("alias."):
                aliases[key[6:]] = val
            i += 2
            continue
        i += 2 if words[i] in ("-C", "--git-dir", "--work-tree", "--namespace") else 1
    if i < len(words) and words[i] in aliases:
        val, rest = aliases[words[i]], words[i + 1 :]
        if val.startswith("!"):
            _analyse(val[1:] + " " + shlex.join(rest), depth + 1, st)
        else:
            _analyse("git " + val + " " + shlex.join(rest), depth + 1, st)


def check_nested(command: str) -> tuple[str, str] | None:
    """Decision for what the command runs once wrappers, quotes and substitutions are unwrapped."""
    st = _State()
    try:
        _analyse(command, 0, st)
    except _Stop:
        pass
    except RecursionError:
        return DENY, "command nested too deeply to check"
    return st.hit


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
