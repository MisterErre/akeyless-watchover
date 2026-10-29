#!/usr/bin/env python3
"""watchover - single entry point for the akeyless-watchover kit.

  scripts/watchover help                 overview of every command
  scripts/watchover help <command>       parameters and examples of one command
  scripts/watchover help skill           commands you can give the Claude skill
  scripts/watchover help --markdown      the full usage guide (docs/usage-guide.md)

This file is the single source of truth for the usage guide: docs/usage-guide.md is
generated from it (`scripts/watchover help --markdown > docs/usage-guide.md`) and a test
fails when the two drift apart.
"""
from __future__ import annotations

import argparse
import os
import subprocess
import sys
from dataclasses import dataclass, field
from typing import Callable

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
sys.path.insert(0, HERE)

VERSION = "1.2.0"

# --------------------------------------------------------------------------------------
# Skill commands (what you type to Claude). Mirrored in skill/akeyless-watchover/SKILL.md.
# --------------------------------------------------------------------------------------


@dataclass
class SkillCommand:
    name: str
    args: str
    purpose: str
    delivers: str
    example: str


SKILL_COMMANDS: list[SkillCommand] = [
    SkillCommand("help", "[command]",
                 "Show this guide, or the details of one skill command.",
                 "The command table, parameters and examples.",
                 "/akeyless-watchover help design"),
    SkillCommand("design", "<diagram | description of BUs, apps, environments, personas>",
                 "Translate an organisation/structure diagram into Akeyless configuration.",
                 "Path tree, access matrix, YAML model (roles, auth methods, folders), access expectations, "
                 "plan expectations, CLI equivalent.",
                 "/akeyless-watchover design <paste or attach the diagram>"),
    SkillCommand("change", "<access request in plain words>",
                 "Change existing access with the smallest possible model diff.",
                 "Diff of model/roles/<bu>.yaml (and auth_methods.yaml if needed), new expectations, "
                 "who must approve (CODEOWNERS).",
                 "/akeyless-watchover change give fraud-analysts read on /payments/+/prod/*"),
    SkillCommand("review", "<model files, merge-request diff or plan output>",
                 "Review a proposed change for least privilege, guard violations and blast radius.",
                 "Findings by severity, failing guards, missing expectations, plan red flags (replacements).",
                 "/akeyless-watchover review <paste the plan>"),
    SkillCommand("pipeline", "[github | gitlab] [repository]",
                 "Set up the governance repository: bootstrap identity, CI, CODEOWNERS, state.",
                 "bootstrap.tfvars, CI file, variables to create, step-by-step order.",
                 "/akeyless-watchover pipeline gitlab group/akeyless-governance"),
    SkillCommand("import", "[what to export: everything / a type / one user's view] [export directory or REPORT.md]",
                 "Export existing config (RBAC, auth methods incl. OIDC, folders, custom fields, key policies, "
                 "PKI issuers, account settings) and translate it into Terraform.",
                 "The exact `watchover export` command (model or --hcl mode, filters), then resolution of every "
                 "REPORT.md item and the import checklist until the plan shows imports only.",
                 "/akeyless-watchover import the OIDC auth method and everything alice@example.com can reach"),
    SkillCommand("conjur", "<Conjur policy YAML>",
                 "Migrate from CyberArk Conjur: secrets via the Gateway, RBAC via translation.",
                 "Translated roles, bindings to fill (auth method + sub-claims), migration resource, cut-over plan.",
                 "/akeyless-watchover conjur <attach policy files>"),
    SkillCommand("pki", "<certificate requirements>",
                 "Design private/public CA issuers and who may request certificates.",
                 "pki.yaml (CA keys, issuers), requester roles, expiry forwarder, CLI to issue/revoke.",
                 "/akeyless-watchover pki internal TLS for *.payments.internal, 90 days, auto-renew"),
    SkillCommand("harden", "[current settings or concerns]",
                 "Account-level hardening.",
                 "governance.yaml: account_settings (Terraform), account_settings_cli (CLI), custom fields, "
                 "key policies, event forwarders.",
                 "/akeyless-watchover harden"),
    SkillCommand("gateway", "<who administers which Gateway, SIEM target>",
                 "Gateway admin plane and audit-log forwarding.",
                 "gateway.yaml (allowed_access, log_forwarding), gateway_api setup.",
                 "/akeyless-watchover gateway platform admins full, PKI team targets only, Splunk"),
    SkillCommand("verify", "[persona | path]",
                 "Prove who can access what.",
                 "access_expectations.yaml checks, `watchover simulate` / `watchover verify` commands, "
                 "Impersonate As steps.",
                 "/akeyless-watchover verify can the checkout pods read refunds prod?"),
    SkillCommand("cli", "<task>",
                 "Exact Akeyless CLI commands for a task (break-glass, bootstrap, one-off checks).",
                 "Commands checked against the CLI reference, with the equivalent model change.",
                 "/akeyless-watchover cli create a temporary read rule for 60 minutes"),
    SkillCommand("explain", "<topic>",
                 "Explain an Akeyless concept precisely (sub-claims, deny, wildcards, anti-escalation...).",
                 "A short answer with the verified facts and VERIFY caveats.",
                 "/akeyless-watchover explain sub-claims AND/OR"),
]

# --------------------------------------------------------------------------------------
# CLI tools
# --------------------------------------------------------------------------------------


@dataclass
class Tool:
    name: str
    summary: str
    parser: Callable[[], argparse.ArgumentParser]
    run: Callable[[list[str]], int]
    needs_akeyless: bool
    examples: list[str] = field(default_factory=list)
    env: list[tuple[str, str]] = field(default_factory=list)


def _module_tool(module: str) -> tuple[Callable, Callable]:
    def parser():
        return __import__(module).build_parser()

    def run(argv):
        try:
            __import__(module).main(argv)
        except SystemExit as e:
            return int(e.code or 0) if not isinstance(e.code, str) else 1
        return 0
    return parser, run


def _shell(script: str, argv: list[str], env: dict | None = None) -> int:
    return subprocess.run(["bash", os.path.join(HERE, script), *argv], env={**os.environ, **(env or {})}).returncode


def _token_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(prog="watchover token",
                                 description="Exchange a CI OIDC/JWT for a short-lived Akeyless token (REST POST /auth, "
                                             "access-type jwt). Prints the token.")
    ap.add_argument("--api", help="Akeyless API (default: $AKEYLESS_API or https://api.akeyless.io)")
    ap.add_argument("--access-id", help="access ID of the CI auth method (default: $AKEYLESS_ACCESS_ID)")
    ap.add_argument("--jwt", help="the CI-issued JWT (default: $CI_JWT; prefer the env var - arguments are visible in the process list)")
    return ap


def _token_run(argv):
    a = _token_parser().parse_args(argv)
    env = {k: v for k, v in {"AKEYLESS_API": a.api, "AKEYLESS_ACCESS_ID": a.access_id, "CI_JWT": a.jwt}.items() if v}
    return _shell("akl_ci_token.sh", [], env)


def _build_parser() -> argparse.ArgumentParser:
    return argparse.ArgumentParser(prog="watchover build-skill",
                                   description="Build dist/akeyless-watchover.zip (SKILL.md + references/ + template/) "
                                               "for upload to Claude or unzip into ~/.claude/skills/.")


def _build_run(argv):
    _build_parser().parse_args(argv)
    return _shell("build_skill.sh", [])


def _test_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(prog="watchover test",
                                 description="Run the complete offline test suite (no Akeyless account needed): "
                                             "fmt, validate, terraform test, guard messages, export round trip, bootstrap tests, "
                                             "access simulation, script tests, guide drift check.")
    ap.add_argument("--tool", choices=["terraform", "tofu"], default="terraform", help="IaC binary to use")
    ap.add_argument("--skip-iac", action="store_true", help="only run the Python checks")
    return ap


def _test_run(argv):
    a = _test_parser().parse_args(argv)
    steps = []
    if not a.skip_iac:
        for d, extra in (("terraform", True), ("bootstrap", False)):
            wd = os.path.join(REPO, d)
            steps += [([a.tool, "fmt", "-check", "-recursive"], wd), ([a.tool, "init", "-backend=false", "-input=false"], wd),
                      ([a.tool, "validate"], wd), ([a.tool, "test"], wd)]
            if extra:
                steps.append((["bash", "tests/guard_messages.sh", a.tool], wd))
                steps.append((["bash", "tests/export_roundtrip.sh", a.tool], wd))
    steps += [([sys.executable, os.path.join(HERE, "akl_simulate.py"), "--model", "terraform/model",
                "--expectations", "terraform/model/access_expectations.yaml"], REPO),
              ([sys.executable, "-m", "pytest", "-q", "scripts/tests"], REPO)]
    for cmd, wd in steps:
        print(f"\n$ {' '.join(cmd)}   (in {os.path.relpath(wd, REPO) or '.'})", flush=True)
        rc = subprocess.run(cmd, cwd=wd).returncode
        if rc != 0:
            print(f"\nFAILED: {' '.join(cmd)}", file=sys.stderr)
            return rc
    print("\nall checks passed")
    return 0


_sim = _module_tool("akl_simulate")
_ver = _module_tool("akl_verify")
_exp = _module_tool("akl_export")
_cj = _module_tool("conjur2akeyless")
_acc = _module_tool("akl_account_settings")

TOOLS: list[Tool] = [
    Tool("test", "Run every offline check (what CI runs).", _test_parser, _test_run, False,
         ["scripts/watchover test", "scripts/watchover test --tool tofu"]),
    Tool("simulate", "Offline: evaluate access_expectations.yaml against the model.", _sim[0], _sim[1], False,
         ["scripts/watchover simulate --model terraform/model --expectations terraform/model/access_expectations.yaml --explain"]),
    Tool("verify", "Live: compare expectations with describe-permissions run as each persona's CLI profile.",
         _ver[0], _ver[1], True,
         ["scripts/watchover verify --expectations terraform/model/access_expectations.yaml"]),
    Tool("export", "Export existing config and translate it: YAML model + import blocks, or plain Terraform (--hcl).",
         _exp[0], _exp[1], True,
         ["scripts/watchover export --out export/ --profile admin --exclude '^/governance/auth/ci-terraform$'",
          "scripts/watchover export --out export/ --profile admin --types auth-methods --only sso",
          "scripts/watchover export --out export/ --profile admin --persona-auth-method /governance/auth/sso-entra-oidc "
          "--persona-claim email=alice@example.com --persona-claim groups=grp-akl-payments-admins",
          "AKEYLESS_ACCESS_ID=p-... AKEYLESS_ACCESS_KEY=... scripts/watchover export --out export/ --profile admin --hcl --generate",
          "scripts/watchover export --out export2/ --from-dir export/raw     # offline replay"]),
    Tool("conjur", "Translate Conjur policy into model roles + identity bindings.", _cj[0], _cj[1], False,
         ["scripts/watchover conjur root.yml prod.yml --item-prefix /conjur --out export/conjur"]),
    Tool("account-settings", "Apply account_settings_cli (settings the provider cannot manage) with the CLI.",
         _acc[0], _acc[1], True,
         ["scripts/watchover account-settings --governance terraform/model/governance.yaml --dry-run",
          "AKEYLESS_TOKEN=$(scripts/watchover token) scripts/watchover account-settings --governance terraform/model/governance.yaml"],
         [("AKEYLESS_TOKEN", "token used when --token is not given")]),
    Tool("token", "CI: exchange the pipeline JWT for an Akeyless token.", _token_parser, _token_run, True,
         ["CI_JWT=$JWT AKEYLESS_ACCESS_ID=p-xxxx scripts/watchover token"],
         [("AKEYLESS_API", "API base URL"), ("AKEYLESS_ACCESS_ID", "CI auth method access ID"), ("CI_JWT", "CI-issued JWT")]),
    Tool("build-skill", "Package the skill ZIP.", _build_parser, _build_run, False,
         ["scripts/watchover build-skill"]),
]
TOOL_BY_NAME = {t.name: t for t in TOOLS}

# --------------------------------------------------------------------------------------
# Help rendering
# --------------------------------------------------------------------------------------


def _params(parser: argparse.ArgumentParser) -> list[tuple[str, str, str, str]]:
    """(flag, value, required/default, description) for every argument, Python-version independent."""
    rows = []
    for act in parser._actions:  # noqa: SLF001 - argparse has no public API for this
        if isinstance(act, argparse._HelpAction):  # noqa: SLF001
            continue
        flag = ", ".join(act.option_strings) if act.option_strings else act.dest
        if act.nargs == 0:
            value = "-"
        elif act.choices:
            value = "|".join(act.choices)
        elif act.nargs in ("+", "*"):
            value = f"{act.dest.upper()}..."
        else:
            value = (act.metavar or act.dest).upper().replace("-", "_")
        if act.required or not act.option_strings:
            req = "required"
        elif isinstance(act, argparse._AppendAction):  # noqa: SLF001
            req = "repeatable"
        elif act.default not in (None, False, argparse.SUPPRESS, []):
            req = f"default {act.default}"
        else:
            req = "optional"
        rows.append((flag, value, req, (act.help or "").replace("|", "/")))
    return rows


def _first_line(text: str | None) -> str:
    return (text or "").strip().splitlines()[0] if text else ""


def render_overview() -> str:
    out = [f"watchover {VERSION} - akeyless-watchover kit", "", "Usage: scripts/watchover <command> [options]", "",
           "Commands:"]
    w = max(len(t.name) for t in TOOLS) + 2
    for t in TOOLS:
        out.append(f"  {t.name:<{w}}{t.summary}{'  [needs Akeyless]' if t.needs_akeyless else ''}")
    out += [f"  {'help':<{w}}This help. 'help <command>', 'help skill', 'help --markdown'.",
            f"  {'version':<{w}}Print the version.", "",
            "Skill commands (type them to Claude, e.g. '/akeyless-watchover help'):",
            "  " + ", ".join(c.name for c in SKILL_COMMANDS), "",
            "Full guide: docs/usage-guide.md"]
    return "\n".join(out)


def render_tool(t: Tool) -> str:
    p = t.parser()
    out = [f"watchover {t.name} - {t.summary}", "", _first_line(p.description), "",
           f"Needs an Akeyless account: {'yes' if t.needs_akeyless else 'no'}", "", "Parameters:"]
    rows = _params(p)
    if not rows:
        out.append("  (none)")
    for flag, value, req, desc in rows:
        out.append(f"  {flag:<26} {value:<14} {req:<22} {desc}")
    if t.env:
        out += ["", "Environment:"] + [f"  {k:<26} {v}" for k, v in t.env]
    out += ["", "Examples:"] + [f"  {e}" for e in t.examples]
    return "\n".join(out)


def render_skill() -> str:
    out = ["Skill commands - type them to Claude.",
           "Claude Code: '/akeyless-watchover <command> [args]'.  Claude (web/desktop): 'akeyless-watchover <command> [args]'",
           "or simply describe the task; the skill also triggers without a command.", ""]
    for c in SKILL_COMMANDS:
        out += [f"  {c.name} {c.args}", f"      {c.purpose}", f"      delivers: {c.delivers}", f"      e.g. {c.example}", ""]
    return "\n".join(out).rstrip()


def _esc(text: str) -> str:
    """Escape for a GitHub markdown table cell (keeps <placeholders> visible)."""
    return (text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
            .replace("|", "/").replace("*", "\\*"))


def render_markdown() -> str:
    md = ["<!-- GENERATED by `scripts/watchover help --markdown` - edit scripts/watchover.py, not this file. -->",
          f"# akeyless-watchover usage guide (v{VERSION})", "",
          "Two ways to use akeyless-watchover:", "",
          "1. **Talk to Claude** with the skill installed: use a *skill command* (below) or just describe the task.",
          "2. **Run the kit** in your governance repository with `scripts/watchover <command>` (Python 3.10+, `pyyaml`;",
          "   Terraform >= 1.7 or OpenTofu >= 1.8; the `akeyless` CLI for live commands).", "",
          "`scripts/watchover help` prints everything in this guide in the terminal.", "",
          "## 1. Skill commands (Claude)", "",
          "Claude Code: `/akeyless-watchover <command> [args]`. Claude (web/desktop): write",
          "`akeyless-watchover <command> [args]` or `/akeyless-watchover ...` - or simply describe the task; the skill also",
          "triggers without a command.", "",
          "| Command | Arguments | Purpose | Delivers | Example |", "|---|---|---|---|---|"]
    for c in SKILL_COMMANDS:
        md.append(f"| `{c.name}` | {_esc(c.args)} | {_esc(c.purpose)} | {_esc(c.delivers)} | `{c.example}` |")
    md += ["", "## 2. Kit commands (`scripts/watchover`)", "",
           "| Command | Summary | Needs Akeyless |", "|---|---|---|"]
    for t in TOOLS:
        md.append(f"| [`{t.name}`](#watchover-{t.name}) | {_esc(t.summary)} | {'yes' if t.needs_akeyless else 'no'} |")
    md += ["| `help [command\\|skill] [--markdown]` | Help in the terminal; `--markdown` regenerates this guide. | no |",
           "| `version` | Print the version. | no |", ""]
    for t in TOOLS:
        p = t.parser()
        md += [f"### watchover {t.name}", "", _esc(_first_line(p.description) or t.summary), ""]
        rows = _params(p)
        if rows:
            md += ["| Parameter | Value | Required / default | Description |", "|---|---|---|---|"]
            md += [f"| `{f}` | {_esc(v)} | {_esc(r)} | {_esc(d)} |" for f, v, r, d in rows]
        else:
            md.append("No parameters.")
        if t.env:
            md += ["", "| Environment variable | Meaning |", "|---|---|"] + [f"| `{k}` | {v} |" for k, v in t.env]
        md += ["", "```bash"] + t.examples + ["```", ""]
    md += ["## 3. Typical sessions", "",
           "**New design**", "```text", "/akeyless-watchover design <diagram>",
           "-> review the five artifacts -> commit model changes -> scripts/watchover test -> merge request", "```", "",
           "**Access change**", "```text", "/akeyless-watchover change <request>",
           "-> scripts/watchover simulate ... -> merge request (plan in CI) -> merge (apply)", "```", "",
           "**Existing account**", "```text", "scripts/watchover export --out export/ --profile admin ...",
           "/akeyless-watchover import export/REPORT.md -> move files -> plan shows only imports -> apply", "```", "",
           "**Conjur**", "```text", "scripts/watchover conjur policy.yml --out export/conjur",
           "/akeyless-watchover conjur export/conjur/bindings.yaml -> fill bindings -> gateway migration -> cut-over", "```", "",
           "## 4. Exit codes", "",
           "| Code | Meaning |", "|---|---|",
           "| 0 | success / all expectations met |",
           "| 1 | check failed (mismatch, drift, failed step) |",
           "| 2 | usage, model or execution error |", "",
           "More: [model-reference.md](model-reference.md) for every YAML key, [cli.md](cli.md) for raw Akeyless CLI",
           "commands, [testing-and-verification.md](testing-and-verification.md)."]
    return "\n".join(md) + "\n"


def cmd_help(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(prog="watchover help")
    ap.add_argument("topic", nargs="?")
    ap.add_argument("--markdown", action="store_true")
    a = ap.parse_args(argv)
    if a.markdown:
        sys.stdout.write(render_markdown())
    elif a.topic is None:
        print(render_overview())
    elif a.topic == "skill":
        print(render_skill())
    elif a.topic in TOOL_BY_NAME:
        print(render_tool(TOOL_BY_NAME[a.topic]))
    else:
        print(f"unknown topic '{a.topic}'. Topics: skill, " + ", ".join(TOOL_BY_NAME), file=sys.stderr)
        return 2
    return 0


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    if not argv or argv[0] in ("help", "-h", "--help"):
        return cmd_help(argv[1:])
    if argv[0] in ("version", "--version"):
        print(VERSION)
        return 0
    tool = TOOL_BY_NAME.get(argv[0])
    if tool is None:
        print(f"unknown command '{argv[0]}'\n\n{render_overview()}", file=sys.stderr)
        return 2
    if len(argv) > 1 and argv[1] in ("-h", "--help"):
        print(render_tool(tool))
        return 0
    return tool.run(argv[1:])


if __name__ == "__main__":
    sys.exit(main())
