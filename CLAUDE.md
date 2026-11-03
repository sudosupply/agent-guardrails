@AGENTS.md

## Claude Code

- Project instructions are in AGENTS.md (imported above). Its Guardrails section is mandatory.
- `.claude/settings.json` denies reading `.env` and key files, force-pushes, history rewrites and the broadest `rm -rf` commands, asks before other risky commands, and runs `.guardrails/guard.py` before every Bash, Read, Edit and Write call. If either blocks you, stop and tell the user what you needed. Don't look for a workaround.
- Personal, uncommitted notes go in `CLAUDE.local.md`.
