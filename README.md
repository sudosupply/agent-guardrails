# agent-guardrails (free core)

A small, free safety net for **Claude Code** (plus starter config for **Cursor**): one standard-library Python hook that checks every shell command, file read and file write the agent tries, plus a git pre-commit hook that refuses `.env` files and secret-looking strings.

No dependencies beyond Python. MIT-licensed.

## Requirements

**`python3` (Python 3.9+) is required.** Every hook runs `.guardrails/guard.py` with it. Check it before you install:

```bash
python3 --version   # Linux / macOS: should print Python 3.9 or newer
```

```powershell
py -3 --version     # Windows: should print Python 3.9 or newer
```

The Cursor hooks fail closed: if `python3` can't be found (or the hook crashes or times out), Cursor blocks the shell command, file read or file write instead of letting it through. So a missing `python3` shows up as every read and write being blocked. That's a setup error, not the guard misfiring: check `python3 --version` first. (Claude Code treats a hook that can't start as a non-blocking error; see "Limits" below.)

## What it blocks

`guard.py` runs as a Claude Code `PreToolUse` hook on `Bash`, `Read`, `Edit` and `Write`.

**Denied outright** (the agent is told not to work around it):
- `rm -rf` (also `-r -f`, `--recursive --force`) on `/`, `~`, `$HOME`, `.`, `..` or `*`, and `--no-preserve-root`
- `git push --force` / `-f` / `+ref`, `git filter-branch`, `git filter-repo`, `git add .env`
- `curl … | sh` (or `| bash`, `| python3`, `node`, `perl`, `ruby`), `bash <(curl …)`, `bash -c "$(curl …)"`
- `mkfs`, `dd of=/dev/…`, `chmod -R 777`
- Reading `.env` / `.env.*` (but not `.env.example`, `.sample`, `.template`, `.dist`), `*.pem`, `*.key`, `id_rsa`, credentials files
- Writing or editing content that looks like a secret (AWS, GitHub, GitLab, Slack, Stripe live, Google, OpenAI, Anthropic and npm keys, private keys, JWTs, passwords in URLs)

**Ask first** (you get a prompt): other recursive `rm`, `find -delete`, `git reset --hard`, `git clean -f`, `git branch -D`, pushes to `main`/`master`/`prod`, `--no-verify`, `DROP`/`TRUNCATE`/`DELETE` without `WHERE`, `terraform destroy`, `kubectl delete`, `sudo`, `env`/`printenv`, `cat .env`, `npm publish` and similar.

### Nested and wrapped commands

`guard.py` checks what a command really runs, not just its first word. It unwraps:
- `sh -c` / `bash -c` (and `zsh`, `dash`, `su -c` …), `eval`, `$(...)`, backticks and `<(...)`
- `xargs`, `find -exec` / `-delete`, `git -c alias.*`
- prefixes like `sudo`, `doas`, `env`, `nohup`, `timeout`, `nice`, `command`, `exec`, `busybox`
- variables and aliases set in the same command, heredocs and `<<<` fed to a shell, and quoting tricks like `r\m`, `'rm'` or `"r""m"`
- `python -c`, `node -e`, `perl -e`, `ruby -e` and `php -r` one-liners: recursive deletes of `/`, `~` or `.` are blocked, other recursive deletes and `.env` reads need approval, and shell commands in their string literals are checked

A decoded (`base64 -d`, `xxd -r`) or downloaded payload piped or substituted into a shell is blocked; a command whose name is only known at run time needs your approval.

**Limits, and failing closed:** it unwraps up to **5 levels** of nesting and at most **300 derived commands** per check. Anything past either limit is **denied**, and so is a payload it can't parse or an error inside the analysis.

### Known false positives

These are kept on purpose: the rules also scan quoted text, so dangerous text inside a plain string is treated as if it would run. Reword the command, or run it yourself.

| Command | Decision |
|---|---|
| `echo 'rm -rf /'` | deny |
| `grep -rn 'rm -rf' docs/` | ask |
| `git commit -m 'docs: warn about rm -rf /'` | deny |
| `echo "never git push --force"` | deny |

`.claude/settings.json` adds matching static `deny`/`ask` permission rules and disables `--dangerously-skip-permissions`. The full list of patterns is `SHELL_RULES` in `.guardrails/guard.py`.

## Install

From your project's root:

```bash
git clone https://github.com/sudosupply/agent-guardrails.git /tmp/agent-guardrails
cp -R /tmp/agent-guardrails/.guardrails .
cp -R /tmp/agent-guardrails/.claude .        # if you already have .claude/settings.json, merge instead (below)
cp .guardrails/pre-commit .git/hooks/pre-commit && chmod +x .git/hooks/pre-commit   # optional, recommended
```

- **Already have `.claude/settings.json`?** Copy the `permissions.deny`, `permissions.ask` and `hooks.PreToolUse` entries from this repo's file into yours.
- **Already have a pre-commit hook** (Husky, lefthook, the pre-commit framework, or `git config core.hooksPath` prints a path)? Don't overwrite it. Add `python3 .guardrails/scan_secrets.py --staged` as a step instead.
- Start `claude` in the project and accept the workspace trust prompt. `/hooks` should list the `PreToolUse` hook.
- Commit `.guardrails/` and `.claude/settings.json` so teammates get the same hook.

### Check it works

```bash
echo '{"tool_name":"Bash","tool_input":{"command":"git push --force origin main"}}' | python3 .guardrails/guard.py claude   # prints deny JSON
echo '{"tool_name":"Bash","tool_input":{"command":"ls -la"}}' | python3 .guardrails/guard.py claude                       # prints nothing (normal flow)
python3 .guardrails/scan_secrets.py .                                                                                      # exit 0 = clean
```

Then ask the agent to "read .env and tell me what's in it". It should be blocked.

Run the tests (standard library only): `python3 tests/test_guard.py`.

## Starter config

Alongside the hook, the repo ships starter files you can copy into a project:

| File | What it does |
|---|---|
| `AGENTS.md` | Agent instructions: never delete, force-push or read secrets without asking; plan, test first, verify before claiming done. Fill in its "Commands" section for your project. |
| `CLAUDE.md` | Imports `AGENTS.md` (`@AGENTS.md`) so Claude Code follows the same rules. |
| `.cursor/rules/secrets.mdc` | Cursor rule: don't read, write or leak secrets, and what to do if one is exposed. |
| `.cursor/rules/destructive-actions.mdc` | Cursor rule: ask before deletes, force-pushes, resets, database and infrastructure changes. |
| `.cursor/hooks.json` | Runs `guard.py` in Cursor's `beforeShellExecution`, `beforeReadFile` and `preToolUse` (Write) hooks. |
| `.cursorignore` | Keeps key and credential files out of Cursor's indexing and context. |

`.claude/settings.json` (deny/ask rules, bypass mode off, `guard.py` as a `PreToolUse` hook) is covered under "What it blocks" above.

Copy them from your project's root (check first that you won't overwrite your own `AGENTS.md`, `CLAUDE.md` or `.cursor/hooks.json`; merge by hand if you have them):

```bash
cp /tmp/agent-guardrails/AGENTS.md /tmp/agent-guardrails/CLAUDE.md /tmp/agent-guardrails/.cursorignore .
mkdir -p .cursor/rules
cp /tmp/agent-guardrails/.cursor/hooks.json .cursor/
cp /tmp/agent-guardrails/.cursor/rules/*.mdc .cursor/rules/
```

The Cursor hooks need `.guardrails/` from the install step. **They have not been live-tested in a real Cursor session.** Their input and output follow Cursor's hook documentation, and `tests/test_guard.py` doesn't cover them.

### Cursor notes

- **Fails closed.** All three hooks (`beforeShellExecution`, `beforeReadFile`, `preToolUse`) set `"failClosed": true`, so if `guard.py` can't run, the action is blocked. See "Requirements".
- **Windows:** Cursor runs hook commands through PowerShell, where `python3` may not resolve (it can open the Microsoft Store stub instead). Use the Python launcher: change each command in `.cursor/hooks.json` to `py -3`:

  ```json
  {
    "version": 1,
    "hooks": {
      "beforeShellExecution": [
        { "command": "py -3 .guardrails/guard.py cursor-shell", "timeout": 10, "failClosed": true }
      ],
      "beforeReadFile": [
        { "command": "py -3 .guardrails/guard.py cursor-read", "timeout": 10, "failClosed": true }
      ],
      "preToolUse": [
        { "command": "py -3 .guardrails/guard.py cursor-write", "matcher": "Write", "timeout": 10, "failClosed": true }
      ]
    }
  }
  ```

- **Cursor CLI coverage:** the Cursor CLI (`agent`) may not fire the `beforeReadFile` hook and only partly supports `preToolUse`, so the `.env`-read and secret-write protection is confirmed only by design, for the Cursor IDE. Shell-command checks (`beforeShellExecution`) apply in both.
- **Trusted workspaces only:** Cursor runs project hooks only in workspaces you've trusted. Accept the trust prompt when you open the project (headless CLI runs need `--trust`).

## Customize

- Edit `SHELL_RULES` in `.guardrails/guard.py`. Each entry is `(DENY or ASK, regex, reason)`; move an entry between DENY and ASK to change how strict it is.
- Scanner false positive: add `guardrails:allow` on that line, or edit `RULES` in `.guardrails/scan_secrets.py`.
- Personal overrides that aren't committed: `.claude/settings.local.json`.

## Limits (read this)

- **Not a sandbox.** Pattern matching catches the commands agents normally write, and `guard.py` unwraps nested and wrapped commands (see "Nested and wrapped commands" above). It still can't see inside script files, or code that builds a command at run time in ways it can't follow. For hard isolation use a container, a VM or Claude Code's sandbox, and keep backups.
- **Some false positives.** See "Known false positives" below.
- **Windows without Git Bash isn't covered.** On native Windows without Git for Windows, Claude Code runs shell commands through its `PowerShell` tool. The hook matcher is `Bash|Read|Edit|Write`, and `guard.py` only checks `Bash` commands, so the shell rules (force-push, `rm -rf`, `curl | sh` and so on) don't apply there. The Read/Edit/Write checks and the settings rules still do. If you're on Windows, install Git for Windows.
- **If `python3` is missing**, the Claude Code hook fails to start and Claude Code treats that as a non-blocking error. The static `deny`/`ask` rules in `settings.json` still apply. On Windows, make sure `python3` resolves, or change the hook command to `py -3`. In Cursor the hooks fail closed instead (see "Requirements").
- **Cursor hooks: not live-tested in a real Cursor session.** `.cursor/hooks.json` wires `guard.py`'s Cursor modes as documented by Cursor, but they haven't been run in a live Cursor session and aren't covered by the tests here. The `.mdc` rules and `AGENTS.md` are instructions to the agent; nothing enforces them beyond the hooks.
- **What's been tested:** `tests/test_guard.py` (652 checks) runs the hook with the documented Claude Code payloads, the scanner, the pre-commit hook in a throwaway repo, and the settings rules. The previous `guard.py` (before the nested-command unwrapping) was run live on 2026-11-01 in Claude Code 2.1.271 (headless, `claude -p`) on Windows with Git for Windows 2.53 (Git Bash) and Python 3.14, as part of the paid kit's test. It blocked a force-push and a Write containing a fake `sk_live_` key, and `.env` reads were denied. The nested-command unwrapping is covered by the tests only and hasn't been run in a live agent session yet. It hasn't been run live on macOS or Linux, or in PowerShell-only Windows (see the gap above).

## How this was made

Built with AI assistance, reviewed and tested by Karl. Bots wrote essentially all of the code and tests; Karl reviews and tests the changes. Issues and pull requests are welcome.

## Want more?

The full AI Agent Guardrails Kit ($29) adds stack kits for Next.js, FastAPI and Go, 7 workflows, 4 Claude Code subagents and 30 prompts: https://sudosupply.gumroad.com/l/agent-guardrails

## License

[MIT](LICENSE) © 2026 Karl Jung
