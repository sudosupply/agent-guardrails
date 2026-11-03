# Changelog

## Unreleased

Starter config added on top of the existing hook:
- `AGENTS.md` and `CLAUDE.md` (imports `@AGENTS.md`).
- `.cursor/rules/secrets.mdc` and `.cursor/rules/destructive-actions.mdc`.
- `.cursor/hooks.json` wiring `guard.py`'s Cursor modes (not yet tested in a live Cursor session).
- `.cursorignore` for key and credential files.
- README: "Starter config" section; `.gitignore`: `CLAUDE.local.md`.

## v0.1.0 (2026-11-01)

First public release of the free core, taken from the AI Agent Guardrails Kit v0.1.2:
- `.guardrails/guard.py`, `.guardrails/scan_secrets.py` and `.guardrails/pre-commit`, unchanged from the kit.
- `.claude/settings.json`: deny/ask permission rules, bypass mode disabled, the `PreToolUse` hook wired to `guard.py`.
- `tests/test_guard.py`: 312 checks (Claude Code hook payloads, scanner, pre-commit flow, settings rules).
