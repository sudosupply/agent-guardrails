# Changelog

## Unreleased

Starter config added on top of the existing hook:
- `AGENTS.md` and `CLAUDE.md` (imports `@AGENTS.md`).
- `.cursor/rules/secrets.mdc` and `.cursor/rules/destructive-actions.mdc`.
- `.cursor/hooks.json` wiring `guard.py`'s Cursor modes (not yet tested in a live Cursor session).
- `.cursorignore` for key and credential files.
- README: "Starter config" section; `.gitignore`: `CLAUDE.local.md`.

Nested and wrapped commands in `guard.py`:
- Checks what a command really runs: `sh -c`/`bash -c` (and zsh, dash, su -c ...) nested up to 5 levels, `eval`, `$(...)`, backticks, `<(...)`, `xargs`, `find -exec`/`-delete`, `git -c alias.*`, wrappers (`sudo`, `env`, `nohup`, `timeout`, `busybox` ...), same-command variables and aliases, heredocs and `<<<` fed to a shell, and quoting tricks (`r\m`, `'rm'`, `"r""m"`).
- `python -c`, `node -e`, `perl -e`, `ruby -e`, `php -r`: recursive deletes of `/`, `~` or `.` are blocked, other recursive deletes and `.env` reads need approval, and shell commands in string literals are checked.
- Fails closed: deeper than 5 levels, more than 300 derived commands, an unparsable payload, or a crash in the analysis blocks.
- `base64 -d`/`xxd -r` output or a download piped or substituted into a shell is blocked; a command name computed at run time needs approval.
- New rules: `git push --mirror` needs approval; `.env` reads via `grep`, `rg`, `awk`, `sed`, `sort` and similar need approval.
- Tests: `tests/nested_cases.py`; `tests/test_guard.py` now runs 652 checks (was 316).

## v0.1.0 (2026-11-01)

First public release of the free core, taken from the AI Agent Guardrails Kit v0.1.2:
- `.guardrails/guard.py`, `.guardrails/scan_secrets.py` and `.guardrails/pre-commit`, unchanged from the kit.
- `.claude/settings.json`: deny/ask permission rules, bypass mode disabled, the `PreToolUse` hook wired to `guard.py`.
- `tests/test_guard.py`: 312 checks (Claude Code hook payloads, scanner, pre-commit flow, settings rules).
