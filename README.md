# agent-guardrails (free core)

A small, free safety net for **Claude Code**: one standard-library Python hook that checks every shell command, file read and file write the agent tries, plus a git pre-commit hook that refuses `.env` files and secret-looking strings.

No dependencies. Python 3.9+. MIT-licensed.

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

## Customize

- Edit `SHELL_RULES` in `.guardrails/guard.py`. Each entry is `(DENY or ASK, regex, reason)`; move an entry between DENY and ASK to change how strict it is.
- Scanner false positive: add `guardrails:allow` on that line, or edit `RULES` in `.guardrails/scan_secrets.py`.
- Personal overrides that aren't committed: `.claude/settings.local.json`.

## Limits (read this)

- **Not a sandbox.** Pattern matching catches the commands agents normally write. It doesn't stop a determined workaround, such as a script that deletes files or an encoded `bash -c` string. For hard isolation use a container, a VM or Claude Code's sandbox, and keep backups.
- **Windows without Git Bash isn't covered.** On native Windows without Git for Windows, Claude Code runs shell commands through its `PowerShell` tool. The hook matcher is `Bash|Read|Edit|Write`, and `guard.py` only checks `Bash` commands, so the shell rules (force-push, `rm -rf`, `curl | sh` and so on) don't apply there. The Read/Edit/Write checks and the settings rules still do. If you're on Windows, install Git for Windows.
- **If `python3` is missing**, the hook fails to start and Claude Code treats that as a non-blocking error. The static `deny`/`ask` rules in `settings.json` still apply. On Windows, make sure `python3` resolves, or change the hook command to `py -3`.
- **Claude Code only.** `guard.py` also has Cursor hook modes in its code, but this repo ships no Cursor config and they aren't covered by the tests here.
- **What's been tested:** `tests/test_guard.py` (312 checks) runs the hook with the documented Claude Code payloads, the scanner, the pre-commit hook in a throwaway repo, and the settings rules. The same `guard.py` was run live in Claude Code on Windows 11 as part of the paid kit, where it blocked `cat .env`, a Write containing a fake `sk_live_` key and `git push --force`. Whether Git Bash was installed during that test hasn't been confirmed, so treat the PowerShell gap above as open. It hasn't been run live on macOS or Linux.

## How this was made

Built with AI assistance, reviewed and tested by Karl. Bots wrote essentially all of the code and tests; Karl reviews and tests the changes. Issues and pull requests are welcome.

## Want more?

The full AI Agent Guardrails Kit ($29) adds Cursor support, AGENTS.md/CLAUDE.md templates, stack kits and review workflows: https://sudosupply.gumroad.com/l/agent-guardrails

## License

[MIT](LICENSE) © 2026 Karl Jung
