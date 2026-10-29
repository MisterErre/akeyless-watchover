# Akeyless REST API or CLI?

## Short answer

They are two clients of **the same operations**. Neither one can read or export configuration that
the other can't. Choose by where the command runs and how it authenticates, not by what it can reach.

## Evidence

* The Akeyless OpenAPI specification (Go SDK v5.0.x) has 666 operations, 665 of them `POST`.
  659 of their request schemas are declared in Akeyless's Go package `go/src/client/commands`,
  which holds the CLI command definitions. The REST API and the CLI flags come from the same
  structs, so a CLI flag is the API field in kebab-case (`--role-name` = `role-name`).
* `akeyless <command> --json` prints the response document of the matching API operation. This
  repository proves the equivalence: the exporter reads the same fixture account through the
  CLI, through REST and from saved JSON, and a test requires byte-identical output
  (`test_transports_produce_identical_output`).
* The Terraform provider uses the REST API (Go SDK). Anything Terraform reads, the API returns.

## Differences that do matter

| | CLI | REST API |
|---|---|---|
| Authentication | profiles in `~/.akeyless/profiles`, interactive SAML/OIDC browser login (`akeyless configure`) | send `token` in every JSON body; get one from `POST /auth` (any access type, e.g. `jwt` in CI) |
| Installation | binary (S3 download or brew) that runners must be allowed to fetch | HTTPS to `api.akeyless.io` or your Gateway only |
| Command names | `folder get`, `list-groups`, `auth-method create oidc`, `policy list` | `/folder-get`, `/list-group`, `/auth-method-create-oidc`, `/policy-list` |
| Gateway operations | `--gateway-url https://<gw>:8000` on each command | base URL `https://<gw>:8000/api/v2` |
| Client-side helpers | `set-role-rule --file-rules` (bulk JSON; the API takes one rule per call), `--jq-expression`, `connect` (SRA sessions), `agent`, `mcp`, `update` | none |
| Output | JSON with `--json`, text otherwise | always JSON |

`/configure` and `/connect` also appear in the specification, because it's generated from the CLI
commands. They're client workflows (profiles, SSH/RDP sessions): don't build on them over REST (VERIFY).

## Decision rules

| Situation | Use |
|---|---|
| Any persistent change (roles, auth methods, folders, issuers, settings...) | **Terraform** (REST via the provider), through the pipeline |
| A person exploring or exporting with their SSO login | **CLI** (`watchover export --transport cli --profile <sso-profile>`) |
| CI jobs: exports, drift reports, verification without the CLI binary | **REST** (`watchover token` -> `watchover export --transport api`) |
| Locked-down runners that can't download binaries | **REST** |
| Secure Remote Access sessions, the local agent, MCP | **CLI** (client-side features) |
| One-off bulk rule changes during an incident | CLI `set-role-rule --file-rules`, then codify in Git |
| An operation documented only in the API reference | **REST** (the CLI usually has it under a similar name: check `-h`) |

## Did the CLI unlock more exports?

Not by itself: the reads are the same. Going through the full list of read operations
(76 `list-*`, `get-*` and `describe-*` calls) did show families the exporter wasn't using yet.
They're now exported with `--hcl`:

| Family | Read operation | Terraform resources |
|---|---|---|
| Targets | `list-targets` | `akeyless_target_*` (aws, azure, gcp, k8s and hashi_vault confirmed from the provider's constants; other types matched by name and marked VERIFY) |
| Groups (OIDC apps) | `list-groups` / `/list-group` | `akeyless_group` |
| Gateway | `gateway-get-config` | `akeyless_gateway_defaults`, `_cache`, `_remote_access`, `_log_forwarding_<type>`, `_migration_<type>`, `_allowed_access` |

Still not exportable through either client:
* Event forwarders: `get-event-forwarder` reads one by name, and there is no list.
* Rotated and dynamic secret definitions: `rotated-secret-list` and `dynamic-secret-list` exist,
  but their producer types aren't yet mapped to provider resources.
* Secret values: excluded on purpose.

For ad-hoc SQL inventory queries outside Terraform, the community also publishes a Steampipe plugin
(`akeyless-community/akeyless`, tables such as `akeyless_target` and `akeyless_gateway`).

## In this kit

```bash
# person with an SSO CLI profile
scripts/watchover export --out export/ --transport cli --profile my-sso
# CI, no CLI binary
export AKEYLESS_TOKEN=$(CI_JWT=$JWT AKEYLESS_ACCESS_ID=p-xxxx scripts/watchover token)
scripts/watchover export --out export/ --transport api --hcl --types targets,groups,gateway \
  --gateway-api https://gw.example.com:8000/api/v2
```
