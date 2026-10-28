---
name: akeyless-watchover
description: Use for Akeyless governance: path/folder design, access roles, rules, auth methods, sub-claims, PKI issuers, account settings via CLI and Terraform, incl. turning RBAC diagrams into IaC.
---

# akeyless-watchover - Akeyless governance as code

Scope: the **control plane inside Akeyless** - path/folder design, Access Roles and rules, Auth
Methods and associations (sub-claims), management-plane visibility, Gateway admin access, PKI
issuers/CA keys, account policy, event forwarders, brownfield import and Conjur migration.
Out of scope unless asked: Gateway deployment and consumer integrations.

Facts here were verified against docs.akeyless.io, the Akeyless OpenAPI/Go SDK v5.0.x and the
source + schema of Terraform provider `akeyless-community/akeyless` **v2.0.5**. **VERIFY** marks
what no primary source confirms - say so to the user instead of presenting it as fact.

## Bundled files (when installed from the ZIP / repository)

- `references/` - full documentation: `rbac-model.md`, `path-and-role-design.md`,
  `model-reference.md` (every YAML key), `terraform.md`, `pipeline.md`, `cli.md`,
  `testing-and-verification.md`, `brownfield-import.md`, `conjur-migration.md`, `pki.md`,
  `limitations.md`. Read the one matching the task before answering in depth.
- `template/` - the tested delivery kit: `terraform/` (data-driven HCL + YAML model + tests),
  `bootstrap/` (CI identity), `scripts/` (simulator, verifier, exporter, Conjur translator,
  account settings, CI token), `ci/` (GitHub/GitLab pipelines, CODEOWNERS).
If they are missing (skill installed as SKILL.md only), the source is
`github.com/MisterErre/akeyless-watchover`; otherwise build from §4 of this file.

## 0. Ground rules

1. Never invent a CLI flag or Terraform argument. Check `akeyless <cmd> -h` and
   `terraform providers schema -json`.
2. Every design answer delivers: (a) path tree, (b) access matrix, (c) YAML model diff,
   (d) `access_expectations.yaml` checks + plan expectations, (e) CLI equivalent for
   break-glass/bootstrap.
3. Secrets never go into YAML or Git: model keys ending in `_var` name entries of sensitive
   variables (`auth_method_secrets`, `event_forwarder_secrets`, `gateway_secrets`).
4. Ask before guessing: identity source per persona, environment segregation, who may change
   RBAC, break-glass owner.
5. Before handing over code: `terraform fmt -check && terraform validate && terraform test`,
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

## 3. Using the delivery kit (template/)

```
terraform/   versions.tf main.tf auth_methods.tf roles.tf governance.tf pki.tf gateway.tf outputs.tf
             model/{auth_methods,folders,governance,pki,gateway,access_expectations}.yaml model/roles/<bu>.yaml
             tests/model.tftest.hcl tests/fixtures/* tests/guard_messages.sh
bootstrap/   CI OAuth2/JWT auth method + terraform-plan / terraform-apply roles (separate state)
scripts/     akl_simulate.py akl_verify.py akl_export.py conjur2akeyless.py akl_account_settings.py akl_ci_token.sh
ci/          github/akeyless-governance.yml gitlab/.gitlab-ci.yml CODEOWNERS.example
```

Workflows:

| Request | Do |
|---|---|
| "Design RBAC for this diagram" | §2 -> edit `model/roles/*.yaml`, `auth_methods.yaml`, `access_expectations.yaml` -> run offline tests -> show the five artifacts |
| "Add/change access for team X" | change only that BU's role file + expectations; mention CODEOWNERS approval |
| "Set up the repo/pipeline" | `bootstrap/` once (admin), copy `ci/` template, set variables (references/pipeline.md) |
| "Import what we already have" | `scripts/akl_export.py` -> REPORT.md -> import blocks -> plan with no changes (references/brownfield-import.md) |
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

## 6. CLI essentials (details: references/cli.md)

Families: `auth-method create <type>`, `target create <type>`, `rotated-secret|dynamic-secret create <type>`,
`folder create`; roles/PKI hyphenated (`create-role`, `set-role-rule`, `assoc-role-am`,
`update-assoc`, `delete-assoc`, `delete-role-rule`, `get-role`, `list-roles`, `update-role`,
`create-pki-cert-issuer`, `create-dfc-key`, `get-pki-certificate`, `revoke-certificate`).
Global: `--profile`, `--token`, `--json`, `--jq-expression`. Write booleans as `--flag=true`.
CI token without stored secrets: REST `POST /auth` `{"access-id","access-type":"jwt","jwt"}` -> `token`
(`scripts/akl_ci_token.sh`), then `--token`.

## 7. Limitations and VERIFY items (details: references/limitations.md)

Say these explicitly when relevant: no per-rule TF resource; no TF rename; temporary rules are
CLI-only and reverted by apply; secrets in state; no RBAC users/groups; deny does not cover SRA;
K8s/LDAP auth need Gateway config; Conjur RBAC is not migrated by Akeyless; one Gateway per
provider alias. VERIFY: plan-identity minimum reads, capability for certificate issuance,
`ara-rule` via TF, template brace syntax, `/a/*` vs `/a`, `rules_type` strings, CLI behaviour of
`describe-permissions` without access, Conjur migration item names.
