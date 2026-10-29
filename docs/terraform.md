# Terraform reference implementation (`terraform/`)

Data-driven: governance lives in YAML, the HCL is generic. Tested offline with OpenTofu 1.10 and
provider 2.0.5 (`validate`, `test` with a mocked provider); the repository CI also runs HashiCorp
Terraform. Requires Terraform >= 1.7 or OpenTofu >= 1.8.

| File | Manages |
|---|---|
| `versions.tf` | provider pin `~> 2.0`, JWT login, `akeyless.gateway` alias, endpoint variables |
| `main.tf` | model loading, **guards**, folders |
| `auth_methods.tf` | one resource block per auth method type, `prevent_destroy` |
| `roles.tf` | roles (authoritative rules) and role <-> auth method associations |
| `governance.tf` | custom fields, key policies, account settings subset, event forwarders |
| `pki.tf` | CA signer keys (DFC, self-signed CA cert) and PKI issuers |
| `gateway.tf` | Gateway allowed access, log forwarding (syslog/splunk), Conjur migration |
| `outputs.tf` | access IDs, role names |

## Inputs

| Variable | Purpose |
|---|---|
| `pipeline_access_id`, `pipeline_jwt` | CI identity (bootstrap output) and CI-issued JWT |
| `akeyless_api` | default `https://api.akeyless.io` |
| `gateway_api` | Gateway API for gateway objects; `null` or `""` disables them |
| `auth_method_secrets`, `event_forwarder_secrets`, `gateway_secrets` | sensitive maps referenced by `*_var` keys |
| `naming` | `role_prefix` / `auth_method_prefix` (set to `""` to disable; `null` means the default) |
| `allow_ara_rules` | opt-in for `ara-rule` |
| `model_dir` | model location (tests point it to fixtures) |

## Guards (fail the plan, never the apply)

`terraform_data.model_guards` preconditions; every resource depends on it.

| Guard | Fixture proving it |
|---|---|
| duplicate role across files | `dup` |
| absolute names, no trailing `/` | - |
| naming prefixes | `bad_prefix` |
| supported auth method types | - |
| supported rule types (ara opt-in) | `bad_rule_type`, `ara_allowed` |
| capabilities valid per rule type | `bad_capability` |
| deny rules contain only deny | `deny_mixed` |
| SRA: approval_authority without request_access | `sra_conflict` |
| `/*` beyond list/deny (or read on role/auth-method rules) needs `allow_root_scope` | `root_scope`, `root_allowed` |
| management-plane values | `bad_mgmt` |
| associations only to modelled auth methods (or `allow_external_auth_methods`) | `unknown_am` |
| `force_sub_claims` auth methods require sub-claims on every association | `missing_subclaims` |
| issuer: signer xor ca_target; auto_renew needs destination_path; CRL/OCSP/ACME/public CA need gw_cluster_url | `bad_issuer` |
| custom field object types, event forwarder types/events, teams requirements, periodic runner needs `every`, slack/teams need `url_var` | `bad_event`, `bad_periodic`, `slack_no_url` |
| gateway objects need `gateway_api`; valid gateway permissions; auth_method xor access_id; log forwarding type | `bad_gateway`, `gateway_objects_need_gateway_api`, `empty_gateway_api_is_unset` |

`tests/guard_messages.sh` proves each negative fixture fails with the **intended** message
(`expect_failures` alone only proves that *some* guard failed).

## Provider facts this code relies on (verified in v2.0.5 source/schema)

1. `akeyless_role.rules` is authoritative; there is no per-rule resource.
2. `assoc_auth_method` inside `akeyless_role` is deprecated - associations are separate resources.
   The role only reads associations back when its own block is used, so there is no drift.
3. `name` is ForceNew on roles, auth methods, folders, issuers, keys, targets, static secrets;
   `role_name`/`am_name` on associations. Rename = destroy + create (new access ID for auth methods).
4. `delete_protection`: string on auth methods/roles/folders/static secrets/certificates, bool on
   `akeyless_pki_cert_issuer` and `akeyless_dfc_key`.
5. Not marked sensitive in the schema: `akeyless_auth_method_oidc.client_secret`, computed
   `akeyless_auth_method_k8s.private_key` - always feed through sensitive variables.
6. `jwt_login.jwt` must be set in HCL (validation fails otherwise, despite the
   `AKEYLESS_AUTH_JWT` env fallback in the provider code).
7. Env fallbacks: `AKEYLESS_GATEWAY`; without a login block `AKEYLESS_ACCESS_ID` + `AKEYLESS_ACCESS_KEY`.
8. Role names do not suppress leading-slash differences (auth methods and associations do).
9. `akeyless_account_settings` is partial and its destroy is a no-op.
10. `akeyless_pki_cert_issuer.ttl` is a string in seconds; `key_usage` default
    `DigitalSignature,KeyAgreement,KeyEncipherment`.
11. Import IDs: object name; associations `"<role>:<auth method>"` or `"<role>:<assoc_id>"`.
12. Refreshing `akeyless_static_secret` reads the secret value (keep values out of this state).
