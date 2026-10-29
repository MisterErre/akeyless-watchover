# Limitations, workarounds and open verifications

## Not possible (platform or provider 2.0.5)

| Limitation | Consequence | What this repo does |
|---|---|---|
| No per-rule resource; `akeyless_role.rules` authoritative | all rules of a role in one place; console edits reverted | YAML merge per role; nightly drift job |
| Names are ForceNew everywhere | rename = destroy + create; auth methods get a new access ID | `prevent_destroy`, delete protection, naming guards; CLI `update-role --new-name` for roles |
| Temporary rules (`--ttl`) CLI/API-only | removed by the next apply on that role | exporter skips them; use access requests for JIT |
| Partial `akeyless_account_settings`, destroy is a no-op | bound IPs, locks, client types, rotation limits, usage events not in TF | `account_settings_cli` + `akl_account_settings.py` in the apply job |
| ARA: no `ara_reports_access`; `ara-rule` undocumented | - | `allow_ara_rules` opt-in after verification |
| No write-only/ephemeral arguments | secrets in state | secret values kept out of this state; state treated as a vault |
| `akeyless_folder` has no `type`/`accessibility` | - | item folders only |
| No RBAC users/groups | human scope = IdP claims | `force_sub_claims`, CODEOWNERS on role files |
| `deny` does not apply to SRA | - | use SRA capabilities |
| K8s/LDAP auth need Gateway-side config | - | out of scope (Gateway) |
| Conjur RBAC not migrated by Akeyless | - | `conjur2akeyless.py` |
| One Gateway per provider alias | - | one state/workspace per Gateway cluster |
| Event forwarders cannot be listed | not exportable, not compared by `reconcile` | `watchover forwarder` scaffolds them; `terraform plan` shows drift |
| `reconcile` compares 5 families only | PKI issuers, forwarders, Gateway, account settings and targets are not compared | listed in REPORT.md; `terraform plan` is the authoritative drift check |
| GitHub Enterprise Server OIDC | Akeyless must fetch the JWKS of `https://<ghe-host>/_services/token` | the instance must expose it to Akeyless (network decision, not code) |

## Not verified against a live account (marked VERIFY)

* Minimum read rights of the plan identity (`bootstrap/`).
* Capability needed to issue a certificate from an issuer.
* `ara-rule` through the provider.
* Sub-claim template syntax `{{x}}` vs `{x}`.
* `/a/*` matching `/a` itself; operator evaluation order (simulator assumptions).
* `access_info.rules_type` strings (exporter); exact CLI behaviour of `describe-permissions` when
  the caller has no access (verifier flag).
* Item names produced by the Conjur migration.
* Export: `target_type` strings other than aws, azure, gcp, k8s and hashi_vault (matched by name);
  the CLI command name `list-groups` (REST `/list-group`); the shape of `admins.allowed_access`
  and the log-forwarding type in `gateway-get-config`; `/configure` and `/connect` over REST.
* HCL export: the CLI command names of the detail reads (`target-get-details`, `get-group`, `gateway-get-*`,
  `gateway-list-migration`) are taken from the REST paths. Attributes the provider fills with custom read logic
  are kept as `# raw` comments, not translated: the PKI issuer `ttl` format, `expiration_event_in`,
  `allowed_extra_extensions`, the log-forwarding `output_format`, and the log-forwarding types other than
  syslog. The detail fixtures are built from the Go SDK structs; they were not captured from a live account.
* Reconcile: which exported fields are provider defaults (shown as "only in Akeyless", not proposed
  unless `--include-unmodelled`) and which model fields the export cannot read ("only in the repository").
* GitHub Enterprise Cloud with data residency (`*.ghe.com`): the OIDC issuer differs from
  github.com; set it explicitly after checking your enterprise's documentation.

Everything else in this repository was checked against docs.akeyless.io, the Akeyless OpenAPI/Go
SDK and the provider source/schema, and the code is covered by offline tests.
