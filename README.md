# akeyless-watchover

Akeyless governance as code: paths, access roles, auth methods and sub-claims, account settings,
PKI, event forwarders and Gateway administration, modelled in YAML and delivered by Terraform from
one repository. It has two parts: a **skill** that any AI agent can use, whatever the model, and a
tested **kit** run with `scripts/watchover`.

**Reference: [docs/akeyless-watchover-manual.pdf](docs/akeyless-watchover-manual.pdf)**. It lists every command with its options, how
it works, its exit codes and examples. The Markdown version is [docs/usage-guide.md](docs/usage-guide.md);
`scripts/watchover help <command>` shows the same entry in the terminal.

## Commands

| Skill commands (to your AI agent) | Kit commands (`scripts/watchover`) |
|---|---|
| `help` `design` `change` `review` `pipeline` `import` `reconcile` `conjur` `pki` `harden` `gateway` `verify` `cli` `explain` | `test` `simulate` `verify`* `export`* `reconcile`* `forwarder` `conjur` `account-settings`* `token`* `build-skill` `install-skill` `validate-skill` `mcp` `help` `version` |

\* calls Akeyless (live); all other commands are offline.

Exports from Akeyless keep their structure. `export --hcl` turns `raw/<dir>/<name>.json` into a complete
`hcl/<dir>/<name>.tf`, with attributes taken from the provider's read code, secrets as variables and
untranslated fields as comments ([docs/brownfield-import.md](docs/brownfield-import.md)).

## Set-up

```bash
pip install pyyaml pytest                       # Python 3.10+; Terraform >= 1.7 or OpenTofu >= 1.8
scripts/watchover test --tool tofu              # every offline check

# skill, for any agent (folders per agent: docs/agents.md)
scripts/watchover install-skill --agent claude|codex|copilot|cursor|gemini|agents [--scope user] [--project DIR]
scripts/watchover mcp --repo DIR                # MCP server: kit tools, docs, skill prompts
scripts/watchover build-skill                   # dist/akeyless-watchover.zip + prompt pack for chat-only assistants
```

Governance repository (GitHub, GitHub Enterprise or GitLab): copy `terraform/`, `bootstrap/`, `scripts/` and a `ci/` template. Run
`bootstrap/` once as an admin (CI identity), then deliver each change by merge request
(checks + plan), merge (apply) and the nightly drift check. See [docs/pipeline.md](docs/pipeline.md).
`watchover reconcile` compares the repository with Akeyless and writes a report and patch for review. It
never commits or pushes ([docs/reconcile.md](docs/reconcile.md)).

## Layout

```text
terraform/   generic HCL + model/ (YAML) + tests/       bootstrap/   one-time CI identity
scripts/     watchover and its tools                    ci/          GitHub / GitLab templates
skill/       SKILL.md (Agent Skills format)             docs/        reference PDF, topic documents
AGENTS.md    instructions for AI coding agents working on this repository
```

## Correctness

Facts come from docs.akeyless.io, the Akeyless OpenAPI/Go SDK v5.0.x and the source and schema of
provider v2.0.5. Anything unconfirmed is marked **VERIFY** ([docs/limitations.md](docs/limitations.md)).

The offline tests run on Terraform and OpenTofu in CI:
- 22 Terraform test runs;
- 15 proofs that each guard fires with the intended message;
- 4 bootstrap runs;
- 109 Python tests, plus a translation self-test of all 76 mapped resource types.
