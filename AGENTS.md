# AGENTS.md

Instructions for AI coding agents working in this repository. Cursor, Claude Code (through `CLAUDE.md`) and other tools that read `AGENTS.md` all follow this file. Many of these rules are also enforced by a hook, `.guardrails/guard.py`, and a pre-commit secret scanner, `.guardrails/scan_secrets.py`.

## Guardrails (read first)

These rules override speed and convenience. If a task seems to need breaking one, stop and ask.

**Never delete or destroy without explicit approval in this conversation:**
- No `rm -rf` on broad targets (`/`, `~`, `.`, `..`, `*`, or a variable that might be empty). For any bulk delete, show the exact file list first.
- No `git push --force`, `git reset --hard`, `git clean -f`, `git branch -D` or history rewrites. Do not push at all unless asked.
- No `DROP`, `TRUNCATE`, `DELETE` without `WHERE`, or database resets outside a local dev database.
- Prefer reversible moves: a new branch, a new commit, moving files instead of deleting them.

**Never read or leak secrets:**
- Do not open, print, copy or summarize `.env` files, private keys, credential files or tokens. Read `.env.example` to learn variable names.
- Do not put secrets in code, tests, logs, commit messages, PR text or chat output. Refer to them by variable name.
- Do not run `env` or `printenv`, or echo secret variables. Check that a variable is set without printing it: `test -n "$API_KEY" && echo set`.
- If you find a committed secret, stop and tell the user. It has to be rotated, not just deleted.

**When a guardrail blocks you:** do not retry with a different spelling, a script or another tool. Explain what you wanted to do and why, and let the user decide.

## How to work

1. **Understand before editing.** Read the files you will change and their callers.
2. **Plan non-trivial work.** For anything touching more than one file, write a short plan (files, steps, how you will verify) before you start. Update it if reality differs.
3. **Test first for behavior changes.** Write or update a test that fails, then change the code until it passes. Never delete, skip or weaken a failing test to make a build pass.
4. **Make the smallest change that solves the problem.** No drive-by refactors or formatting churn.
5. **Verify, then report.** Run the checks in "Commands" for the code you touched, and report what you ran and the result. Never claim something works without running it. If you could not run a check, say so.
6. **Stop and ask** when requirements are unclear, a step is destructive, or you need a new dependency.

## Commands

<!-- Fill these in for your project. The agent runs them to verify its work. -->

- Install: `<install command>`
- Lint: `<lint command>`
- Tests: `<test command>`
