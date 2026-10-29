#!/usr/bin/env bash
# Builds the skill for any agent (kept for compatibility; same as `scripts/watchover build-skill`):
#   dist/akeyless-watchover/ + .zip                 Agent Skills package (SKILL.md, references/, template/)
#   dist/prompt-pack/ + akeyless-watchover-prompt-pack.zip   for assistants without skill support
# Install with `scripts/watchover install-skill --agent <agent>`; see docs/agents.md.
set -euo pipefail
exec python3 "$(cd "$(dirname "$0")" && pwd)/akl_skill.py" build "$@"
