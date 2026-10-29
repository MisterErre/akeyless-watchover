#!/usr/bin/env python3
"""Package, validate and install the akeyless-watchover skill for any AI agent.

The skill follows the open Agent Skills format (https://agentskills.io): a folder named after the skill
with a SKILL.md (YAML frontmatter + instructions), plus references/ and template/ (the tested kit).
Agents that implement the format load it natively; for the others, `build` also writes a prompt pack
(system prompt + knowledge files) and `scripts/watchover_mcp.py` exposes the kit over MCP.

  build     dist/akeyless-watchover/ (+ .zip)           Agent Skills package (any compliant agent)
            dist/prompt-pack/ (+ akeyless-watchover-prompt-pack.zip)
                                                         chat assistants without skill support
  install   copy the package into the skills folder an agent scans (project or user scope)
  validate  check a skill folder against the Agent Skills specification
"""
from __future__ import annotations

import argparse
import os
import re
import shutil
import sys
import tempfile
import zipfile

import yaml

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
NAME = "akeyless-watchover"
# Repository layout: skill/<name>/SKILL.md and docs/. Packaged layout (this file in <skill>/template/scripts):
# SKILL.md and references/ one level above the kit root.
_PACKAGED = not os.path.isdir(os.path.join(REPO, "skill", NAME)) and os.path.isfile(os.path.join(os.path.dirname(REPO), "SKILL.md"))
SRC = os.path.dirname(REPO) if _PACKAGED else os.path.join(REPO, "skill", NAME)
DOCS = os.path.join(os.path.dirname(REPO), "references") if _PACKAGED else os.path.join(REPO, "docs")
KIT_DIRS = ["terraform", "bootstrap", "scripts", "ci"]
KIT_EXCLUDE = {".terraform", "__pycache__", ".pytest_cache", "_guard_probe.tftest.hcl", ".terraform.lock.hcl"}

# Where each agent looks for skills (project = relative to the repository, user = home directory).
# Sources: the agents' documentation, checked 2026-10 - see docs/agents.md.
AGENTS: dict[str, dict[str, str]] = {
    "agents":      {"project": ".agents/skills", "user": "~/.agents/skills",
                    "label": "shared .agents/skills (OpenAI Codex, Gemini CLI, Cursor and other agents that read it)"},
    "claude":      {"project": ".claude/skills", "user": "~/.claude/skills", "label": "Claude Code"},
    "codex":       {"project": ".agents/skills", "user": "~/.agents/skills", "label": "OpenAI Codex (CLI, IDE, app)"},
    "copilot":     {"project": ".github/skills", "user": "~/.copilot/skills",
                    "label": "GitHub Copilot (cloud agent, CLI, VS Code agent mode)"},
    "cursor":      {"project": ".cursor/skills", "user": "~/.cursor/skills", "label": "Cursor"},
    "gemini":      {"project": ".gemini/skills", "user": "~/.gemini/skills", "label": "Gemini CLI"},
}

# Agent Skills specification: frontmatter fields and limits
SPEC_FIELDS = {"name", "description", "license", "compatibility", "metadata", "allowed-tools"}
NAME_RE = re.compile(r"^[a-z0-9]+(-[a-z0-9]+)*$")

PROMPT_PREAMBLE = """# akeyless-watchover - instructions for an AI assistant

You are assisting a platform/PAM engineer with Akeyless governance as code. Follow the
instructions below. They come from the akeyless-watchover skill; the knowledge files uploaded with
them (references/*.md) contain the details they point to. You cannot run commands unless your
environment provides a tool for it: when you cannot, give the user the exact commands to run and
say what to check in their output. Never claim to have run a command or verified a fact you did
not; mark unconfirmed facts as VERIFY.

"""

SHORT_PROMPT = """# akeyless-watchover

You assist with Akeyless governance as code: paths, access roles, rules, auth methods and
sub-claims, delivered as a YAML model through Terraform, plus the Akeyless CLI/API.

Before answering any request, read the knowledge file `akeyless-watchover-instructions.md` and
follow it exactly; it defines the commands (help, design, change, review, pipeline, import, conjur,
pki, harden, gateway, verify, cli, explain) and the rules. Read the matching file in references/
before answering in depth (e.g. rbac-model.md, model-reference.md, usage-guide.md).

Rules that always apply:
1. Never invent a CLI flag, Terraform argument or YAML key; if the files do not confirm it, say VERIFY.
2. Secrets never go into YAML or Git: keys ending in _var name entries of sensitive variables.
3. You cannot run commands: give the exact `scripts/watchover ...`, `terraform ...` or `akeyless ...`
   commands and what to check in their output. Never claim results you did not see.
4. Every design answer delivers: path tree, access matrix, YAML model diff, access expectations and
   plan expectations, and the CLI equivalent for break-glass/bootstrap.
"""


# --------------------------------------------------------------------------------------------- helpers
def split_frontmatter(text: str) -> tuple[dict, str]:
    m = re.match(r"^---\n(.*?)\n---\n?(.*)$", text, re.S)
    if not m:
        raise ValueError("SKILL.md must start with YAML frontmatter between '---' lines")
    meta = yaml.safe_load(m.group(1)) or {}
    if not isinstance(meta, dict):
        raise ValueError("frontmatter must be a YAML mapping")
    return meta, m.group(2)


def _copy_kit(dest: str) -> None:
    def ignore(_d, names):
        return [n for n in names if n in KIT_EXCLUDE or n.endswith(".tfstate") or ".tfstate." in n]
    for d in KIT_DIRS:
        shutil.copytree(os.path.join(REPO, d), os.path.join(dest, d), ignore=ignore, symlinks=False)


def _zip(src_dir: str, zip_path: str, root_name: str) -> None:
    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as z:
        for base, dirs, files in os.walk(src_dir):
            dirs.sort()
            for f in sorted(files):
                full = os.path.join(base, f)
                info = zipfile.ZipInfo(os.path.join(root_name, os.path.relpath(full, src_dir)), (2026, 1, 1, 0, 0, 0))
                info.external_attr = (os.stat(full).st_mode & 0o777) << 16
                info.compress_type = zipfile.ZIP_DEFLATED
                with open(full, "rb") as fh:
                    z.writestr(info, fh.read())


# --------------------------------------------------------------------------------------------- build
def build(out: str) -> dict[str, str]:
    """Write the skill package and the prompt pack under `out`. Returns {artefact: path}."""
    out = os.path.abspath(out)
    shutil.rmtree(out, ignore_errors=True)
    skill = os.path.join(out, NAME)
    os.makedirs(os.path.join(skill, "references"))
    shutil.copy(os.path.join(SRC, "SKILL.md"), skill)
    if os.path.isdir(os.path.join(SRC, "agents")):                  # optional per-agent sidecars
        shutil.copytree(os.path.join(SRC, "agents"), os.path.join(skill, "agents"))
    if _PACKAGED and os.path.abspath(out).startswith(os.path.abspath(SRC) + os.sep):
        raise ValueError("--out must be outside the installed skill folder")
    docs = sorted(f for f in os.listdir(DOCS) if f.endswith(".md"))
    for f in docs:
        shutil.copy(os.path.join(DOCS, f), os.path.join(skill, "references", f))
    _copy_kit(os.path.join(skill, "template"))
    problems = validate(skill)
    if problems:
        raise ValueError("built skill is not valid:\n  " + "\n  ".join(problems))
    _zip(skill, os.path.join(out, NAME + ".zip"), NAME)

    meta, body = split_frontmatter(open(os.path.join(SRC, "SKILL.md"), encoding="utf-8").read())
    pack = os.path.join(out, "prompt-pack")
    os.makedirs(os.path.join(pack, "knowledge", "references"))
    with open(os.path.join(pack, "system-prompt.md"), "w", encoding="utf-8") as fh:
        fh.write(PROMPT_PREAMBLE + f"Skill version {meta.get('metadata', {}).get('version', '?')}.\n\n" + body.lstrip())
    with open(os.path.join(pack, "system-prompt-short.md"), "w", encoding="utf-8") as fh:
        fh.write(SHORT_PROMPT)
    shutil.copy(os.path.join(pack, "system-prompt.md"), os.path.join(pack, "knowledge", NAME + "-instructions.md"))
    for f in docs:
        shutil.copy(os.path.join(DOCS, f), os.path.join(pack, "knowledge", "references", f))
    with open(os.path.join(pack, "README.md"), "w", encoding="utf-8") as fh:
        fh.write(PACK_README)
    _zip(pack, os.path.join(out, NAME + "-prompt-pack.zip"), "prompt-pack")
    return {"skill": skill, "skill_zip": os.path.join(out, NAME + ".zip"), "prompt_pack": pack,
            "prompt_pack_zip": os.path.join(out, NAME + "-prompt-pack.zip")}


PACK_README = """# akeyless-watchover prompt pack

For assistants that do not support the Agent Skills format (chat products, plain model APIs).

| File | Use |
|---|---|
| `system-prompt.md` | Full instructions. Use as the system prompt / custom instructions where the size allows (model APIs, project instructions). |
| `system-prompt-short.md` | Under 3,000 characters. Use where instructions are size-limited; it tells the assistant to read the knowledge files. |
| `knowledge/` | Upload as knowledge / project files: the instructions and every reference document. |

The assistant cannot run the kit from a chat-only product: it gives you the commands, you run them
in your governance repository (`scripts/watchover ...`). For tool access without skill support,
connect the MCP server instead (docs/agents.md).
"""


# --------------------------------------------------------------------------------------------- validate
def validate(path: str) -> list[str]:
    """Problems found in a skill folder (empty list = valid)."""
    p: list[str] = []
    f = os.path.join(path, "SKILL.md")
    if not os.path.isfile(f):
        return [f"{path}: SKILL.md not found"]
    text = open(f, encoding="utf-8").read()
    try:
        meta, body = split_frontmatter(text)
    except (ValueError, yaml.YAMLError) as e:
        return [f"SKILL.md: {e}"]
    extra = set(meta) - SPEC_FIELDS
    if extra:
        p.append(f"frontmatter: fields not in the Agent Skills specification: {sorted(extra)}")
    name = meta.get("name")
    if not isinstance(name, str) or not (1 <= len(name) <= 64) or not NAME_RE.match(name):
        p.append("name: 1-64 characters, lowercase letters, digits and single hyphens, no leading/trailing hyphen")
    elif name != os.path.basename(os.path.normpath(path)):
        p.append(f"name '{name}' must match the folder name '{os.path.basename(os.path.normpath(path))}'")
    desc = meta.get("description")
    if not isinstance(desc, str) or not (1 <= len(desc) <= 1024):
        p.append("description: required string of 1-1024 characters")
    comp = meta.get("compatibility")
    if comp is not None and (not isinstance(comp, str) or not (1 <= len(comp) <= 500)):
        p.append("compatibility: string of 1-500 characters")
    md = meta.get("metadata")
    if md is not None and (not isinstance(md, dict) or not all(isinstance(k, str) and isinstance(v, str) for k, v in md.items())):
        p.append("metadata: mapping of string keys to string values")
    at = meta.get("allowed-tools")
    if at is not None and not isinstance(at, str):
        p.append("allowed-tools: space-separated string")
    lines = body.count("\n")
    if lines > 500:
        p.append(f"body has {lines} lines; the specification recommends at most 500 (move detail to references/)")
    for ref in sorted(set(re.findall(r"references/([A-Za-z0-9_.-]+\.md)", body))):
        if os.path.isdir(os.path.join(path, "references")) and not os.path.isfile(os.path.join(path, "references", ref)):
            p.append(f"SKILL.md mentions references/{ref}, which is not in the package")
    return p


# --------------------------------------------------------------------------------------------- install
def target_dir(agent: str, scope: str, project: str, dest: str | None) -> str:
    if dest:
        return os.path.join(os.path.abspath(os.path.expanduser(dest)), NAME)
    base = AGENTS[agent][scope]
    root = os.path.expanduser(base) if scope == "user" else os.path.join(os.path.abspath(project), base)
    return os.path.join(root, NAME)


def install(agent: str, scope: str, project: str = ".", dest: str | None = None, force: bool = False,
            package: str | None = None) -> str:
    target = target_dir(agent, scope, project, dest)
    with tempfile.TemporaryDirectory() as tmp:
        src = package or build(tmp)["skill"]
        if os.path.exists(target):
            if not force:
                raise FileExistsError(f"{target} exists - use --force to replace it")
            shutil.rmtree(target)
        os.makedirs(os.path.dirname(target), exist_ok=True)
        shutil.copytree(src, target)
    return target


# --------------------------------------------------------------------------------------------- CLI
def build_parser_build() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(prog="watchover build-skill",
                                 description="Build the Agent Skills package (dist/akeyless-watchover/ and .zip) and the "
                                             "prompt pack for assistants without skill support (dist/prompt-pack/ and .zip).")
    ap.add_argument("--out", help="output directory, replaced (default: dist/ in the kit root)")
    return ap


def build_parser_install() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(prog="watchover install-skill",
                                 description="Install the skill into the folder an agent scans for skills.")
    ap.add_argument("--agent", required=True, choices=sorted(AGENTS) + ["custom"],
                    help="target agent; 'agents' = the shared .agents/skills folder; 'custom' needs --dest")
    ap.add_argument("--scope", choices=["project", "user"], default="project",
                    help="project = inside --project; user = your home directory")
    ap.add_argument("--project", default=".", help="repository the project-scope skill is installed into")
    ap.add_argument("--dest", help="explicit skills folder (overrides --agent/--scope)")
    ap.add_argument("--force", action="store_true", help="replace an existing installation")
    ap.add_argument("--dry-run", action="store_true", help="print the target folder, change nothing")
    return ap


def build_parser_validate() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(prog="watchover validate-skill",
                                 description="Validate a skill folder against the Agent Skills specification "
                                             "(frontmatter fields and limits, name = folder, body length, referenced files).")
    ap.add_argument("path", nargs="?", help="skill folder (default: this skill)")
    return ap


def _show(path: str) -> str:
    rel = os.path.relpath(path)
    return path if rel.startswith("..") else rel


def main_build(argv=None) -> int:
    a = build_parser_build().parse_args(argv)
    try:
        res = build(a.out or os.path.join(REPO, "dist"))
    except ValueError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    for k in ("skill_zip", "prompt_pack_zip"):
        print(f"built {_show(res[k])} ({os.path.getsize(res[k]) // 1024} KiB)")
    print(f"skill folder: {_show(res['skill'])}/  prompt pack: {_show(res['prompt_pack'])}/")
    return 0


def main_install(argv=None) -> int:
    a = build_parser_install().parse_args(argv)
    if a.agent == "custom" and not a.dest:
        print("error: --agent custom needs --dest", file=sys.stderr)
        return 2
    target = target_dir(a.agent, a.scope, a.project, a.dest)
    if a.dry_run:
        print(target)
        return 0
    try:
        target = install(a.agent, a.scope, a.project, a.dest, a.force)
    except (FileExistsError, ValueError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    print(f"installed {NAME} for {AGENTS.get(a.agent, {}).get('label', a.dest)} in {target}")
    return 0


def main_validate(argv=None) -> int:
    a = build_parser_validate().parse_args(argv)
    path = a.path or SRC
    problems = validate(path)
    for pr in problems:
        print(f"FAIL  {pr}")
    if not problems:
        print(f"ok    {_show(path)} follows the Agent Skills specification")
    return 1 if problems else 0


if __name__ == "__main__":
    cmd, rest = (sys.argv[1], sys.argv[2:]) if len(sys.argv) > 1 else ("", [])
    fn = {"build": main_build, "install": main_install, "validate": main_validate}.get(cmd)
    if fn is None:
        print(__doc__)
        sys.exit(2)
    sys.exit(fn(rest))
