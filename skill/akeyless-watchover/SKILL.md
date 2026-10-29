---
name: akeyless-watchover
description: >-
  Akeyless governance as code. Use for any Akeyless RBAC, governance or IaC task: design or review
  paths, folders, access roles, rules, auth methods and sub-claims; turn an organisation or RBAC
  diagram into a YAML model delivered by Terraform; exact Akeyless CLI/API commands; PKI issuers,
  account settings, event forwarders and Gateway admin access; export existing configuration to
  Terraform; migrate RBAC from CyberArk Conjur; prove who can access what.
compatibility: >-
  Model- and vendor-neutral (Agent Skills format; a single-file prompt pack and an MCP server exist
  for agents without skill support). Running the bundled kit needs a shell with Python 3.10+ and
  pyyaml, Terraform >= 1.7 or OpenTofu >= 1.8, and the akeyless CLI or network access to the
  Akeyless API for live commands.
metadata:
  version: "1.6.0"
  repository: https://github.com/MisterErre/akeyless-watchover
---

# akeyless-watchover - Akeyless governance as code

Scope: the **control plane inside Akeyless** - path/folder design, Access Roles and rules, Auth
Methods and associations (sub-claims), management-plane visibility, Gateway admin access, PKI
issuers/CA keys, account policy, event forwarders, brownfield import and Conjur migration.
Out of scope unless asked: Gateway deployment and consumer integrations.

Facts here were verified against docs.akeyless.io, the Akeyless OpenAPI/Go SDK v5.0.x and the
source + schema of Terraform provider `akeyless-community/akeyless` **v2.0.5**. **VERIFY** marks
what no primary source confirms - say so to the user instead of presenting it as fact.

## Working in any agent

These instructions are written for any AI agent and any model. Adapt to what your environment
allows, and never claim to have run something you did not run:

| Your environment | Do |
|---|---|
| Shell access (coding agents, CLIs, IDE agents) | Run the kit: `scripts/watchover <command>` from the kit root (below). Show real output. |
| `watchover_*` tools available (MCP server `watchover-mcp`) | Call them instead of the shell; read the `watchover://docs/...` resources for references. |
| Files readable, no shell | Read the references; give the user the exact commands to run and what to check in the output. |
| Chat only (prompt pack, no files) | Answer from this text; give exact commands; mark anything you cannot check as VERIFY. |

Locate the material once per task:
- **Kit root** = the directory containing `scripts/watchover`: `template/` next to this file in the
  packaged skill, or the root of the akeyless-watchover / governance repository you are working in.
- **References** = `references/` next to this file, or `docs/` in the repository (same files).
- If neither exists (instructions only), the source is `https://github.com/MisterErre/akeyless-watchover`;
  otherwise build from §4 of this file.

References: `usage-guide.md` (all commands and parameters), `agents.md` (how this skill runs on
each agent), `api-vs-cli.md`, `rbac-model.md`, `path-and-role-design.md`, `model-reference.md`
(every YAML key), `terraform.md`, `pipeline.md`, `cli.md`, `testing-and-verification.md`,
`brownfield-import.md`, `conjur-migration.md`, `pki.md`, `limitations.md`. Read the one matching
the task before answering in depth.

## Commands

The user may start a request with a command - `akeyless-watchover <command> [args]`, or the
skill invocation syntax of their agent (for example `/akeyless-watchover <command>` or
`$akeyless-watchover <command>`) - or just describe the task.
Map plain requests to the closest command. Without arguments, ask for the one missing input.

| Command | Arguments | Deliver |
|---|---|---|
| `help` | [command] | The command table, parameters and examples. |
| `design` | <diagram / description of BUs, apps, environments, personas> | Path tree, access matrix, YAML model (roles, auth methods, folders), access expectations, plan expectations, CLI equivalent. |
| `change` | <access request in plain words> | Diff of model/roles/<bu>.yaml (and auth_methods.yaml if needed), new expectations, who must approve (CODEOWNERS). |
| `review` | <model files, merge-request diff or plan output> | Findings by severity, failing guards, missing expectations, plan red flags (replacements). |
| `pipeline` | [github / gitlab] [repository] | bootstrap.tfvars, CI file, variables to create, step-by-step order. |
| `import` | [what to export: everything / a type / one user's view] [export directory or REPORT.md] | The exact `watchover export` command (model or --hcl mode, filters), then resolution of every REPORT.md item and the import checklist until the plan shows imports only. |
| `reconcile` | [repository URL or checkout] [branch] | `watchover reconcile` run read-only against the repository (e.g. GitHub Enterprise) and Akeyless; REPORT.md explained difference by difference; changes.patch / proposed files / imports.tf handed over for the user to review and commit. |
| `conjur` | <Conjur policy YAML> | Translated roles, bindings to fill (auth method + sub-claims), migration resource, cut-over plan. |
| `pki` | <certificate requirements> | pki.yaml (CA keys, issuers), requester roles, expiry forwarder, CLI to issue/revoke. |
| `harden` | [current settings or concerns] | governance.yaml: account_settings (Terraform), account_settings_cli (CLI), custom fields, key policies, event forwarders (scaffolded with `watchover forwarder`). |
| `gateway` | <who administers which Gateway, SIEM target> | gateway.yaml (allowed_access, log_forwarding), gateway_api setup. |
| `verify` | [persona / path] | access_expectations.yaml checks, `watchover simulate` / `watchover verify` commands, Impersonate As steps. |
| `cli` | <task> | Commands checked against the CLI reference, with the equivalent model change. |
| `explain` | <topic> | A short answer with the verified facts and VERIFY caveats. |

`help`: reply with the content of `references/usage-guide.md` (skill commands, kit commands, every
parameter, examples, exit codes). With an argument (`help design`, `help export`), show only that
command's section. If the references are not available, render the table above and the kit command
list from §3, and point to `scripts/watchover help` in the kit - never invent parameters.

Every command ends with the verification step that applies (offline tests, simulation, plan
review or live verification) and with the VERIFY caveats that touch the answer.

## 0. Ground rules

1. Never invent a CLI flag or Terraform argument. Check `akeyless <cmd> -h` and
   `terraform providers schema -json`.
2. Every design answer delivers: (a) path tree, (b) access matrix, (c) YAML model diff,
   (d) `access_expectations.yaml` checks + plan expectations, (e) CLI equivalent for
   break-glass/bootstrap.
3. **Never commit, push, merge or open pull requests** in the user's governance repository (wherever it is
   hosted, e.g. GitHub Enterprise). Read it (clone, fetch, read files) and deliver changes as files or a
   patch with the commands to apply and verify them; the user reviews and commits.
4. Secrets never go into YAML or Git: model keys ending in `_var` name entries of sensitive
   variables (`auth_method_secrets`, `event_forwarder_secrets`, `gateway_secrets`).
5. Ask before guessing: identity source per persona, environment segregation, who may change
   RBAC, break-glass owner.
6. Before handing over code: `terraform fmt -check && terraform validate && terraform test`,
   `tests/guard_messages.sh`, `scripts/akl_simulate.py` (all offline).

## 1. Akeyless authorization in brief (details: references/rbac-model.md)

- Items, Targets, Roles and Auth Methods are separate slash-path trees; item folders are implicit.
- Identity = Auth Method + token claims. No RBAC users/groups (Akeyless "Groups" are for OIDC apps).
- Default deny. Role = rules + management-plane attributes; bound to auth methods by associations
  with sub-claims (OR within a key, AND across keys, `*`/`?` globs, case-sensitive by default;
  `force_sub_claims` makes sub-claims mandatory).
- Rule types: `item-rule` (default), `target-rule`, `role-rule`, `auth-method-rule` with
  `read, list, create, update, delete, deny`; `sra-rule` with `allow_access, request_access,
  justify_access_only, approval_authority, upload_files, download_files`; `ara-rule` (`allow_access`,
  VERIFY in Terraform). Every capability implies `list`; `deny` overrides all other permissions on
  the path and does not apply to SRA; `approval_authority` cannot be combined with `request_access`.
- Wildcards: trailing `*` or prefix `devops-*`; `+` = one segment. Templated paths from claims
  (`{{x}}` vs `{x}`: VERIFY).
- Management plane: `audit_access` none|own|scoped|all; `analytics_access` none|own|all;
  `gw_analytics_access`, `sra_reports_access`, `event_center_access`, `isi_access`,
  `unlock_secrets`, `approve_access_request` none|scoped|all; `usage_reports_access`,
  `event_forwarders_access` none|all (+ `event_forwarders_name`); `reverse_rbac_access` scoped|all.
- Anti-escalation: non-admins cannot grant what they do not hold; their deny rules are copied to
  roles they create (`restricted_rules`). The RBAC-applying identity must be admin-equivalent.
- Second layer: Gateway Allowed Access (per Gateway) with permissions `defaults, targets,
  classic_keys, automatic_migration, ldap_auth, dynamic_secret, k8s_auth, log_forwarding,
  zero_knowledge_encryption, rotated_secret, caching, event_forwarding, admin, kmip, general,
  rotate_secret_value`.
- `describe-permissions --path P --type item|am|role|target` = the **caller's own** permissions;
  `reverse-rbac` = who reaches P; Console "Impersonate As" = test a persona.

## 2. From a structural diagram to configuration (details: references/path-and-role-design.md)

1. Inventory: BUs, apps, environments, data classes, personas, identity source per persona.
2. Path tree: delegation boundary first, granted dimensions next, most specific last:
   `/<bu>/<app>/<env>/<class>/<secret>`; environment first if prod operators are separate; `+` to
   cross-cut; reserved `/shared`, `/pki/{ca,issuers,certs}`, `/platform`; carve-outs (`break-glass`,
   `pci`) as fixed segments for one `deny`; stable IDs only.
3. Names: roles `/governance/roles/<bu>/<role>`, auth methods `/governance/auth/<idp-or-platform>-<scope>`,
   targets `/targets/<bu>/<app>/<env>/<name>`, issuers `/pki/issuers/<name>`, forwarders `/governance/events/<name>`.
4. Access matrix personas x scopes; one role per (persona x scope x access level).
5. Bindings: humans = one SSO auth method + `groups` sub-claims; workloads = one auth method per
   trust boundary with `bound_*`.
6. Admin plane: only the pipeline holds CRUD on `role-rule`/`auth-method-rule`; humans read,list +
   audit; break-glass role bound to an MFA group with alerting.
7. Write the YAML (`model/roles/<bu>.yaml`, ...) and the expectations; run the simulator.

Role catalogue: `<bu>/<app>-<env>-workload` (read,list + deny carve-outs), `<bu>/team-admin`
(CRUD nonprod, read prod), optional `<bu>/delegated-admin`, `platform/auditors` (item list `/*`,
role/auth-method read `/*`, audit all), `platform/pki-requesters-<x>`, `platform/breakglass`.

## 3. Using the delivery kit (kit root)

```
terraform/   versions.tf main.tf auth_methods.tf roles.tf governance.tf pki.tf gateway.tf outputs.tf
             model/{auth_methods,folders,governance,pki,gateway,access_expectations}.yaml model/roles/<bu>.yaml
             tests/model.tftest.hcl tests/fixtures/* tests/guard_messages.sh
bootstrap/   CI OAuth2/JWT auth method + terraform-plan / terraform-apply roles (separate state)
scripts/     watchover (entry point: test, simulate, verify, export, forwarder, conjur, account-settings, token,
             build-skill, install-skill, validate-skill, mcp, help) + the scripts it dispatches to
ci/          github/akeyless-governance.yml gitlab/.gitlab-ci.yml CODEOWNERS.example
```

Workflows:

| Request | Do |
|---|---|
| "Design RBAC for this diagram" | §2 -> edit `model/roles/*.yaml`, `auth_methods.yaml`, `access_expectations.yaml` -> run offline tests -> show the five artifacts |
| "Add/change access for team X" | change only that BU's role file + expectations; mention CODEOWNERS approval |
| "Set up the repo/pipeline" | `bootstrap/` once (admin), copy `ci/` template, set variables (references/pipeline.md) |
| "Compare the repository with Akeyless / what changed outside Git" | `watchover reconcile --repo-url <ghe url> --profile <read-only>` (or `--repo-dir`) -> explain REPORT.md, let the user choose per difference, hand over changes.patch + proposed/ + imports.tf; verify with `terraform plan`; never commit or push |
| "Import / export what we already have" | `watchover export`: model mode (YAML + import blocks for terraform/) or `--hcl` (Terraform writes plain HCL via `plan -generate-config-out`); filters `--types`, `--only`, `--persona-auth-method/--persona-claim` (one user's view) -> REPORT.md -> plan shows imports only (references/brownfield-import.md) |
| "Migrate from Conjur" | Gateway migration for values + `scripts/conjur2akeyless.py` for RBAC (references/conjur-migration.md) |
| "Certificates" | `pki.yaml` ca_keys/issuers + requester roles + expiry forwarder (references/pki.md) |
| "Prove who can access what" | `akl_simulate.py` offline, `akl_verify.py` live with persona profiles, Impersonate As |
| "Lock down the account" | `governance.yaml` account_settings (TF subset) + account_settings_cli (CLI) + custom fields + key policies |
| "Who administers the Gateway" | `gateway.yaml` allowed_access (needs `gateway_api`) |

Guards that fail the plan (all proven by fixtures): duplicate roles, naming prefixes, unsupported
types, capability sets per rule type, deny-only rules, SRA conflict, root scope without
`allow_root_scope`, management-plane values, associations to unmodelled auth methods (unless
`allow_external_auth_methods`), missing sub-claims on `force_sub_claims` auth methods, issuer
consistency (signer xor ca_target, auto_renew -> destination_path, CRL/OCSP/ACME/public CA ->
gw_cluster_url), event forwarder types/events, gateway objects without `gateway_api`, gateway
permissions.

## 4. Core implementation (if the template is not available)

Model loading and associations (`main.tf`):
```hcl
locals {
  model_dir  = "${path.root}/${var.model_dir}"
  role_files = sort(fileset("${local.model_dir}/roles", "*.yaml"))
  role_docs  = [for f in local.role_files : try(yamldecode(file("${local.model_dir}/roles/${f}")).roles, {})]
  roles      = merge(local.role_docs...)
  associations = {
    for a in flatten([for rn, r in local.roles : [for as in try(r.associations, []) : {
      key            = "${rn}|${as.auth_method}"
      role           = rn
      auth_method    = as.auth_method
      case_sensitive = tostring(try(as.case_sensitive, true))
      sub_claims     = { for k, v in try(as.sub_claims, {}) : k => try(join(",", v), tostring(v)) }
    }]]) : a.key => a
  }
}
```
Roles and associations (`roles.tf`):
```hcl
resource "akeyless_role" "this" {
  for_each     = local.roles
  name         = each.key
  description  = try(each.value.description, null)
  audit_access = try(each.value.audit_access, null) # ...one line per management-plane attribute
  dynamic "rules" {                                  # AUTHORITATIVE
    for_each = try(each.value.rules, [])
    content {
      path       = rules.value.path
      capability = rules.value.capabilities
      rule_type  = try(rules.value.type, "item-rule")
    }
  }
}
resource "akeyless_associate_role_auth_method" "this" {
  for_each       = local.associations
  role_name      = akeyless_role.this[each.value.role].name
  am_name        = try(local.managed_am_names[each.value.auth_method], each.value.auth_method)
  sub_claims     = length(each.value.sub_claims) > 0 ? each.value.sub_claims : null
  case_sensitive = each.value.case_sensitive
}
```
Provider: a `jwt_login` block with `access_id = var.pipeline_access_id` and
`jwt = var.pipeline_jwt`, plus an `alias = "gateway"` provider pointing at the Gateway API for `gateway_*` resources. One resource
block per auth method type (`akeyless_auth_method_{api_key,oidc,saml,oauth2,aws_iam,azure_ad,k8s,universal_identity}`)
with `prevent_destroy`. Tests: `mock_provider "akeyless" {}` in `tests/*.tftest.hcl`.

## 5. Provider 2.0.5 facts to apply every time

1. `akeyless_role.rules` is authoritative; no per-rule resource.
2. Use `akeyless_associate_role_auth_method`, never the deprecated `assoc_auth_method` block.
3. `name` is ForceNew (roles, auth methods, folders, issuers, keys, targets, static secrets);
   rename = destroy + create, new access ID for auth methods. CLI `update-role --new-name` exists.
4. `delete_protection`: string on auth methods/roles/folders/static secrets/certificates, bool on
   `akeyless_pki_cert_issuer` and `akeyless_dfc_key`.
5. Not sensitive in schema: `akeyless_auth_method_oidc.client_secret`, computed
   `akeyless_auth_method_k8s.private_key`.
6. `jwt_login.jwt` must be set explicitly (validation fails otherwise).
7. Env fallbacks: `AKEYLESS_GATEWAY`; without login block `AKEYLESS_ACCESS_ID`/`AKEYLESS_ACCESS_KEY`.
8. `gateway_*` resources need the Gateway API (`:8000/api/v2` or `:8081`).
9. `akeyless_account_settings` is partial; destroy is a no-op. The rest goes through
   `update-account-settings` (admin-only).
10. `akeyless_pki_cert_issuer.ttl` is a string in seconds.
11. Import IDs: object name; associations `"<role>:<auth method>"`.
12. Refreshing `akeyless_static_secret` reads the value: keep secret values out of governance state.
13. State holds API keys, OIDC client secrets, K8s private keys, webhook/Splunk/Conjur secrets.

## 6. API or CLI (details: references/api-vs-cli.md)

Same operations: the OpenAPI request schemas are generated from the CLI command package, and
`--json` prints the API response. Neither one exports more than the other. Choose by context:
Terraform for every persistent change; the CLI for people with SSO profiles and for client-side
features (`connect`, `agent`, `mcp`, `set-role-rule --file-rules`, `--jq-expression`); REST for CI
and locked-down runners (`watchover token` + `watchover export --transport api`). Names can differ
(`list-groups` vs `/list-group`, `folder get` vs `/folder-get`). Gateway calls: CLI `--gateway-url
https://gw:8000`, REST base `https://gw:8000/api/v2`.

## 7. CLI essentials (details: references/cli.md)

Families: `auth-method create <type>`, `target create <type>`, `rotated-secret|dynamic-secret create <type>`,
`folder create`; roles/PKI hyphenated (`create-role`, `set-role-rule`, `assoc-role-am`,
`update-assoc`, `delete-assoc`, `delete-role-rule`, `get-role`, `list-roles`, `update-role`,
`create-pki-cert-issuer`, `create-dfc-key`, `get-pki-certificate`, `revoke-certificate`).
Global: `--profile`, `--token`, `--json`, `--jq-expression`. Write booleans as `--flag=true`.
CI token without stored secrets: REST `POST /auth` `{"access-id","access-type":"jwt","jwt"}` -> `token`
(`scripts/akl_ci_token.sh`), then `--token`.

## 8. Limitations and VERIFY items (details: references/limitations.md)

Say these explicitly when relevant: no per-rule TF resource; no TF rename; temporary rules are
CLI-only and reverted by apply; secrets in state; no RBAC users/groups; deny does not cover SRA;
K8s/LDAP auth need Gateway config; Conjur RBAC is not migrated by Akeyless; one Gateway per
provider alias. VERIFY: plan-identity minimum reads, capability for certificate issuance,
`ara-rule` via TF, template brace syntax, `/a/*` vs `/a`, `rules_type` strings, CLI behaviour of
`describe-permissions` without access, Conjur migration item names.
