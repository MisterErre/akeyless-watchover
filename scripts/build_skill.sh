#!/usr/bin/env bash
# Builds dist/akeyless-watchover.zip: the skill folder at the ZIP root with
#   SKILL.md, references/ (docs) and template/ (terraform, bootstrap, scripts, ci).
# Upload it in Claude (Customize > Skills, or Settings > Capabilities > Skills) or unzip it
# into ~/.claude/skills/ for Claude Code.
set -euo pipefail
root="$(cd "$(dirname "$0")/.." && pwd)"
name="akeyless-watchover"
out="$root/dist/$name"
rm -rf "$root/dist" && mkdir -p "$out/references" "$out/template"
cp "$root/skill/$name/SKILL.md" "$out/"
cp "$root"/docs/*.md "$out/references/"
tar -C "$root" --exclude='.terraform' --exclude='.terraform.lock.hcl' --exclude='__pycache__' \
    --exclude='.pytest_cache' --exclude='*.tfstate*' --exclude='_guard_probe.tftest.hcl' \
    -cf - terraform bootstrap scripts ci | tar -C "$out/template" -xf -
(cd "$root/dist" && zip -qr "$name.zip" "$name")
echo "built dist/$name.zip ($(du -h "$root/dist/$name.zip" | cut -f1))"
