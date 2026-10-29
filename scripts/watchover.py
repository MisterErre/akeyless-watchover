#!/usr/bin/env python3
"""watchover - single entry point for the akeyless-watchover kit.

  scripts/watchover help                 overview of every command
  scripts/watchover help <command>       parameters and examples of one command
  scripts/watchover help skill           commands you can give the skill (any AI agent)
  scripts/watchover help --markdown      the full usage guide (docs/usage-guide.md)

This file is the single source of truth for the usage guide: docs/usage-guide.md is
generated from it (`scripts/watchover help --markdown > docs/usage-guide.md`) and a test
fails when the two drift apart.
"""
from __future__ import annotations

import argparse
import os
import signal
import subprocess
import sys
from dataclasses import dataclass, field
from typing import Callable

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
sys.path.insert(0, HERE)

VERSION = "1.6.1"

# --------------------------------------------------------------------------------------
# Skill commands (what you type to your AI agent). Mirrored in skill/akeyless-watchover/SKILL.md.
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
    SkillCommand("reconcile", "[repository URL or checkout] [branch]",
                 "Compare the governance repository (GitHub Enterprise) with live Akeyless and prepare the changes "
                 "for manual review. Never commits or pushes.",
                 "REPORT.md with every difference and its two resolutions, changes.patch, proposed files, "
                 "imports.tf - to review and commit yourself.",
                 "akeyless-watchover reconcile https://ghe.example.com/platform/akeyless-governance main"),
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
                 "/akeyless-watchover explain should this run through the API or the CLI?"),
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


def _skill_tool(parser: str, runner: str) -> tuple[Callable, Callable]:
    def p():
        return getattr(__import__("akl_skill"), parser)()

    def r(argv):
        return getattr(__import__("akl_skill"), runner)(argv)
    return p, r


_bld = _skill_tool("build_parser_build", "main_build")
_ins = _skill_tool("build_parser_install", "main_install")
_val = _skill_tool("build_parser_validate", "main_validate")


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
_fw = _module_tool("akl_forwarder")
_mcp = _module_tool("watchover_mcp")
_rec = _module_tool("akl_reconcile")
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
          "AKEYLESS_TOKEN=$(scripts/watchover token) scripts/watchover export --out export/ --transport api "
          "--hcl --types targets,groups,gateway --gateway-api https://gw.example.com:8000/api/v2",
          "scripts/watchover export --out export2/ --from-dir export/raw     # offline replay"]),
    Tool("reconcile", "Compare the governance repository (e.g. GitHub Enterprise) with live Akeyless; write a "
         "report and a patch to review. Read-only: never commits or pushes.", _rec[0], _rec[1], True,
         ["scripts/watchover reconcile --repo-url https://ghe.example.com/platform/akeyless-governance.git --profile akl-readonly",
          "scripts/watchover reconcile --repo-dir ~/src/akeyless-governance --ref main --transport api",
          "scripts/watchover reconcile --repo-dir . --export-dir export/ --out /tmp/reconcile",
          "scripts/watchover reconcile --repo-url git@ghe.example.com:platform/akeyless-governance.git --profile ro "
          "--only '^/governance/roles/payments/' --propose-removals"],
         [("AKEYLESS_TOKEN", "api transport: token when --token is not given"),
          ("AKEYLESS_API", "api transport: API URL")]),
    Tool("forwarder", "Scaffold a new event forwarder (model entry or HCL); --import-existing adopts one by name.",
         _fw[0], _fw[1], False,
         ["scripts/watchover forwarder --name /governance/events/secops-mail --type email --email-to secops@example.com "
          "--preset critical --items-source '/*' --auth-method-source '/*'",
          "scripts/watchover forwarder --name /governance/events/pki-slack --type slack --preset certificates "
          "--items-source '/pki/*' --write terraform/model/governance.yaml",
          "scripts/watchover forwarder --name /governance/events/siem --type webhook --url https://siem.example.com/akeyless "
          "--auth-type bearer-token --preset critical --auth-method-source '/*' --format hcl",
          "scripts/watchover forwarder --name /governance/events/legacy-mail --type email --email-to ops@example.com "
          "--event certificate-expired --items-source '/*' --import-existing"]),
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
    Tool("build-skill", "Build the agent-neutral skill package (Agent Skills ZIP) and the prompt pack.",
         _bld[0], _bld[1], False,
         ["scripts/watchover build-skill", "scripts/watchover build-skill --out /tmp/wo-dist"]),
    Tool("install-skill", "Install the skill where an AI agent looks for skills (per-agent folders or any folder).",
         _ins[0], _ins[1], False,
         ["scripts/watchover install-skill --agent codex --project ../akeyless-governance",
          "scripts/watchover install-skill --agent claude --scope user",
          "scripts/watchover install-skill --agent copilot --project . --dry-run",
          "scripts/watchover install-skill --agent custom --dest ~/my-agent/skills --force"]),
    Tool("validate-skill", "Check a skill folder against the Agent Skills specification.",
         _val[0], _val[1], False,
         ["scripts/watchover validate-skill", "scripts/watchover validate-skill dist/akeyless-watchover"]),
    Tool("mcp", "Serve the kit, the docs and the skill commands to any MCP client (stdio).",
         _mcp[0], _mcp[1], False,
         ["scripts/watchover mcp", "WATCHOVER_MCP_LIVE=1 scripts/watchover mcp --repo ~/src/akeyless-governance"],
         [("WATCHOVER_MCP_LIVE", "1 = also expose the commands that call Akeyless (verify, export, account-settings, token)"),
          ("WATCHOVER_REPO", "kit root the tools run in (default: this repository)")]),
]
TOOL_BY_NAME = {t.name: t for t in TOOLS}

# How each command works (shown by `help <command>`, the usage guide and the PDF reference).
SKILL_HOW: dict[str, list[str]] = {
    "help": ["Reads references/usage-guide.md (or the command table in SKILL.md).",
             "With an argument, returns only that command's entry. Parameters are never invented."],
    "design": ["Inventories BUs, applications, environments, data classes, personas and the identity source of each; "
               "asks for whatever is missing.",
               "Derives the path tree `/<bu>/<app>/<env>/...` (delegation boundary first, carve-outs such as "
               "`break-glass` as fixed segments) and the access matrix persona x scope.",
               "Creates one role per persona x scope x access level; binds humans through the SSO auth method + "
               "`groups` sub-claims and workloads through one auth method per trust boundary.",
               "Writes the model files and access_expectations.yaml, then runs `watchover simulate`/`test` "
               "when it can run commands."],
    "change": ["Finds the role file of the owning business unit (model/roles/<bu>.yaml).",
               "Applies the smallest change: a rule, an association, narrower sub-claims - or a new role when no "
               "existing role has the right audience.",
               "Adds a positive and a negative expectation, simulates, and lists the CODEOWNERS approvers."],
    "review": ["Checks the input against the guards, least privilege (root scope, removed deny rules, "
               "associations without sub-claims) and plan red flags (replacements caused by renames).",
               "Reports findings ranked by severity, with the missing expectations."],
    "pipeline": ["Fills bootstrap.tfvars for the CI platform and repository, selects the CI template, lists the "
                 "CI variables (masked or not) and the order of the steps."],
    "import": ["Chooses the export mode (model or --hcl) and filters, and gives the `watchover export` command.",
               "Reads REPORT.md and resolves every item (secrets, unsupported types, external references).",
               "Iterates until the plan shows imports only."],
    "reconcile": ["Clones the repository read-only (or reads a checkout) and runs `watchover reconcile` with a "
                  "read-only Akeyless identity; without a shell, gives the command to run.",
                  "Explains each difference and asks whether Akeyless or the repository is right; adjusts the "
                  "proposal (--only, --include-unmodelled, --propose-removals).",
                  "Hands over the patch and files with the commands to apply and verify them (git apply, "
                  "terraform plan). Never commits, pushes or opens a pull request."],
    "conjur": ["Runs or gives `watchover conjur`; proposes an auth method and sub-claims for each Conjur host and "
               "user in bindings.yaml; adds the Gateway migration entry and a cut-over plan."],
    "pki": ["Writes pki.yaml (CA key, issuers: signer key or public CA target, domains, TTL, auto-renew), the "
            "requester roles, an expiry forwarder and the CLI to issue and revoke."],
    "harden": ["Splits the settings into the Terraform-managed subset (account_settings) and the CLI-only part "
               "(account_settings_cli); adds custom fields, key policies and critical event forwarders.",
               "Always starts with `watchover account-settings --dry-run`."],
    "gateway": ["Writes gateway.yaml: allowed_access (auth method or access ID + permissions) and log forwarding "
                "(syslog or splunk); sets gateway_api. One state per Gateway cluster."],
    "verify": ["Evaluates access with the Akeyless rules (wildcards, deny precedence, sub-claims OR within a key / "
               "AND across keys).",
               "Writes the matching expectation checks and the commands that prove them offline (`simulate`) and "
               "live (`verify`, Impersonate As)."],
    "cli": ["Gives the exact `akeyless` commands, checked against the CLI reference, and the model change that "
            "makes the result permanent (CLI changes to roles are reverted by the next apply)."],
    "explain": ["Answers from the verified references; anything not confirmed by a primary source is marked VERIFY."],
}

TOOL_HOW: dict[str, list[str]] = {
    "test": ["Runs, stopping at the first failure: fmt -check, init -backend=false, validate and `test` (mocked "
             "provider) in terraform/ and bootstrap/; guard_messages.sh (each negative fixture fails with the "
             "intended guard); export_roundtrip.sh; `simulate`; pytest."],
    "simulate": ["Loads model/roles/*.yaml and auth_methods.yaml.",
                 "For each check: selects the roles whose associations match the persona's auth method and "
                 "claims; collects the rules of the right type whose path pattern matches (claim templates "
                 "expanded); a matching deny removes everything.",
                 "Compares the resulting capability set with `expect` (exact match)."],
    "verify": ["For each check whose persona has a `profile`: runs `akeyless describe-permissions --path --type "
               "--json --profile <persona>` and compares `client_permissions` with `expect`.",
               "Personas without a profile are skipped and counted."],
    "export": ["Reads the selected object families through the CLI (`--json`) or the REST API (token); filters by "
               "name, root folder, depth or persona.",
               "Pagination: the CLI returns a `next_page` token even after the last page, so reading stops at the "
               "first EMPTY page; also when the token is missing or repeats, or a page brings nothing new; it "
               "aborts after 10,000 pages instead of looping.",
               "Writes raw/ (JSON, secrets redacted) and REPORT.md (items needing a decision).",
               "Model mode: model/*.imported.yaml + imports.tf for the kit. --hcl: hcl/imports.tf with one import "
               "block per object; --generate runs `plan -generate-config-out` so Terraform writes the resources."],
    "reconcile": ["Gets the repository read-only: shallow clone of --ref with the push URL disabled, or reads "
                  "--repo-dir as it is. Never writes to it, never commits or pushes.",
                  "Exports roles, auth methods, folders, custom fields and key policies from Akeyless (as `export`; "
                  "or uses --export-dir / --from-dir).",
                  "Compares object by object after normalisation (defaults, ordering, *_var secret keys and guard "
                  "switches ignored): changed, only in Akeyless, only in the repository.",
                  "Writes REPORT.md, changes.patch (`git apply`), proposed/ (complete changed files at their "
                  "repository paths, edited in place so comments survive), imports.tf for objects added from "
                  "Akeyless, summary.json and the export used."],
    "forwarder": ["Validates name, type, event types, sources and runner with the same rules as the Terraform guards.",
                  "Builds the model entry; secrets become `*_var` keys of TF_VAR_event_forwarder_secrets.",
                  "Prints YAML (default) or HCL; --write inserts the entry into governance.yaml without touching the "
                  "rest of the file and refuses duplicates; --import-existing adds an import block (ID = name).",
                  "Presets: " + "; ".join(f"{k} = {', '.join(v)}" for k, v in __import__("akl_forwarder").PRESETS.items()) + "."],
    "conjur": ["Parses the policy files (!policy, !variable, !host, !layer, !group, !user, !permit, !grant), "
               "resolving ids against their policy namespace.",
               "Maps privileges to capabilities (execute -> read, read -> list, update -> update) on the migrated "
               "item paths; one role per layer or group; nested grants are flattened.",
               "Writes roles/conjur.yaml, bindings.yaml (host/user -> roles, auth method TODO) and REPORT.md."],
    "account-settings": ["Reads account_settings_cli from governance.yaml; rejects unknown flags and keys Terraform manages.",
                         "Builds one `akeyless update-account-settings` call (lists repeat the flag, booleans as "
                         "=true/false); --dry-run prints it, otherwise runs it with --profile or --token."],
    "token": ["POSTs {access-id, access-type: jwt, jwt} to <api>/auth and prints the token. No credential is stored."],
    "build-skill": ["Copies SKILL.md (+ agents/ sidecar), docs/*.md as references/ and the kit as template/; "
                    "validates the result; zips it.",
                    "Writes the prompt pack: full and short system prompt + knowledge files."],
    "install-skill": ["Builds the package in a temporary folder and copies it to the agent's skills folder "
                      "(project or user scope, or --dest). Never overwrites without --force."],
    "validate-skill": ["Checks SKILL.md: only specification fields; name 1-64 chars, lowercase/digits/hyphens, equal "
                       "to the folder; description <= 1024; compatibility <= 500; metadata string -> string; body "
                       "<= 500 lines; every references/*.md it mentions exists."],
    "mcp": ["JSON-RPC 2.0 over stdin/stdout. Tools are generated from each command's options and run "
            "`scripts/watchover <command>` in the kit root; output and exit code are returned.",
            "Resources: SKILL.md, docs, model files. Prompts: one per skill command (skill instructions + request).",
            "Commands that call Akeyless are listed only with --live."],
}

TOOL_EXITS: dict[str, str] = {
    "test": "0 all passed; otherwise the exit code of the first failing step",
    "simulate": "0 all met; 1 mismatch; 2 model error",
    "verify": "0 all met; 1 mismatch; 2 CLI call failed",
    "export": "0 written; 2 read/HTTP error or invalid options",
    "forwarder": "0 written; 2 invalid input or duplicate (nothing written)",
    "reconcile": "0 no differences; 1 differences found (files written); 2 git, export or model error",
    "conjur": "0 written; 2 unreadable or invalid policy",
    "account-settings": "0 applied/printed; 2 invalid settings; else the CLI's exit code",
    "token": "0 token printed; 1 missing settings or authentication failed",
    "build-skill": "0 written; 2 built skill invalid",
    "install-skill": "0 installed; 2 target exists (no --force) or custom without --dest",
    "validate-skill": "0 valid; 1 problems listed",
    "mcp": "runs until the client closes stdin",
}

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
            "Skill commands (type them to your AI agent, e.g. 'akeyless-watchover help'):",
            "  " + ", ".join(c.name for c in SKILL_COMMANDS), "",
            "Full guide: docs/usage-guide.md"]
    return "\n".join(out)


def render_tool(t: Tool) -> str:
    p = t.parser()
    out = [f"watchover {t.name} - {t.summary}", "", "How it works:"] + [f"  - {h}" for h in TOOL_HOW.get(t.name, [])] + [
           "", f"Needs an Akeyless account: {'yes' if t.needs_akeyless else 'no'}.  Exit codes: {TOOL_EXITS.get(t.name, '-')}",
           "", "Parameters:"]
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
    out = ["Skill commands - type them to your AI agent (any agent that has the skill, the MCP prompts or the prompt pack).",
           "Write 'akeyless-watchover <command> [args]' or your agent's skill syntax ('/akeyless-watchover ...',",
           "'$akeyless-watchover ...'), or simply describe the task; the skill also triggers without a command.",
           "Per-agent setup: docs/agents.md.", ""]
    for c in SKILL_COMMANDS:
        out += [f"  {c.name} {c.args}", f"      {c.purpose}", f"      delivers: {c.delivers}", f"      e.g. {c.example}", ""]
    out.append("How each one works: scripts/watchover help --markdown, or the PDF reference.")
    return "\n".join(out).rstrip()


def _esc(text: str) -> str:
    """Escape for a GitHub markdown table cell (keeps <placeholders> visible)."""
    return (text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
            .replace("|", "/").replace("*", "\\*"))


def render_markdown() -> str:
    md = ["<!-- GENERATED by `scripts/watchover help --markdown` - edit scripts/watchover.py, not this file. -->",
          f"# akeyless-watchover command reference (v{VERSION})", "",
          "Two interfaces:", "",
          "- **Skill commands** - typed to an AI agent that has the skill: `akeyless-watchover <command> [args]` "
          "(or the agent's skill syntax, e.g. `/akeyless-watchover`, `$akeyless-watchover`; MCP prompt "
          "`watchover-<command>`). Set-up per agent: [agents.md](agents.md).",
          "- **Kit commands** - run in the governance repository: `scripts/watchover <command> [options]` "
          "(Python 3.10+ with pyyaml; Terraform >= 1.7 or OpenTofu >= 1.8; the akeyless CLI for live commands).", "",
          "Notation: `<x>` required, `[x]` optional, `a|b` choice. *Live* = calls Akeyless.", "",
          "## Index", "", "| Skill command | Purpose |", "|---|---|"]
    md += [f"| [`{c.name}`](#skill-{c.name}) | {_esc(c.purpose)} |" for c in SKILL_COMMANDS]
    md += ["", "| Kit command | Purpose | Live |", "|---|---|---|"]
    md += [f"| [`{t.name}`](#kit-{t.name}) | {_esc(t.summary)} | {'yes' if t.needs_akeyless else 'no'} |" for t in TOOLS]
    md += ["| `help [command|skill] [--markdown]` | This reference in the terminal. | no |".replace("|skill", "\\|skill"),
           "| `version` | Print the version. | no |", "", "## Skill commands", ""]
    for c in SKILL_COMMANDS:
        md += [f'<a id="skill-{c.name}"></a>', f"### {c.name}", "",
               f"`akeyless-watchover {c.name} {c.args}`", "",
               f"**Does:** {c.purpose}  ", f"**Delivers:** {c.delivers}", "", "**How it works:**", ""]
        md += [f"- {h}" for h in SKILL_HOW.get(c.name, [])]
        md += ["", f"**Example:** `{c.example}`", ""]
    md += ["## Kit commands", ""]
    for t in TOOLS:
        p = t.parser()
        md += [f'<a id="kit-{t.name}"></a>', f"### {t.name}", "",
               f"`scripts/watchover {t.name} [options]` - {_esc(t.summary)} "
               f"{'*Live.*' if t.needs_akeyless else '*Offline.*'}", "", "**How it works:**", ""]
        md += [f"- {h}" for h in TOOL_HOW.get(t.name, [])]
        rows = _params(p)
        md.append("")
        if rows:
            md += ["| Option | Value | Required / default | Description |", "|---|---|---|---|"]
            md += [f"| `{f}` | {_esc(v)} | {_esc(r)} | {_esc(d)} |" for f, v, r, d in rows]
        else:
            md.append("No options.")
        if t.env:
            md += ["", "| Environment variable | Meaning |", "|---|---|"] + [f"| `{k}` | {v} |" for k, v in t.env]
        md += ["", f"**Exit codes:** {TOOL_EXITS.get(t.name, '-')}", "", "```bash"] + t.examples + ["```", ""]
    md += ["## Exit codes (all kit commands)", "", "0 success - 1 check failed (mismatch, invalid skill) - "
           "2 usage, input or execution error. Per command: see each entry."]
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
    if hasattr(signal, "SIGPIPE"):          # `watchover ... | head` ends quietly instead of a BrokenPipeError
        signal.signal(signal.SIGPIPE, signal.SIG_DFL)
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
