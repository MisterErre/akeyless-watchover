# AGENTS.md - instructions for AI coding agents working in this repository

This repository is **akeyless-watchover**: an agent-neutral skill plus a tested kit for Akeyless
governance as code. These instructions apply to any agent (Codex, Copilot, Cursor, Gemini CLI,
Claude Code, Jules, Amp, ...) and any model.

## For Akeyless governance tasks
Follow `skill/akeyless-watchover/SKILL.md`. Inside this repository the kit root is the repository
root and the references are in `docs/`. Run kit commands with `scripts/watchover <command>`
(`scripts/watchover help` lists them).

## For changes to the kit itself
- Run `scripts/watchover test --tool tofu` (or `--tool terraform`) before finishing; everything must pass.
  Python only: `scripts/watchover test --skip-iac`.
- New or changed command/option: update `scripts/watchover.py` (registry), then regenerate
  `scripts/watchover help --markdown > docs/usage-guide.md` and `python3 docs/manual/build.py`.
- Skill commands live in two places that must match: `SKILL_COMMANDS` in `scripts/watchover.py` and the
  table in `skill/akeyless-watchover/SKILL.md` (a test checks it). Keep `SKILL.md` valid:
  `scripts/watchover validate-skill`.
- New Terraform guard: precondition in `terraform/main.tf`, a negative fixture, a `run` in
  `terraform/tests/model.tftest.hcl` and the message in `terraform/tests/guard_messages.sh`.
- Never invent Akeyless CLI flags, API fields or provider arguments. Unconfirmed facts are marked
  **VERIFY** and listed in `docs/limitations.md`.
- Never commit secrets, state files or `export/` output.
- Record user-visible changes in `CHANGELOG.md`; the version is `VERSION` in `scripts/watchover.py`
  and `metadata.version` in `SKILL.md` (a test checks they match).
