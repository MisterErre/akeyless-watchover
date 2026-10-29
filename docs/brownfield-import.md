# Export existing configuration and translate it into Terraform

`watchover export` reads what already exists in an Akeyless account and translates it into
Terraform. It only **reads**: nothing in Akeyless changes until you apply.

## What is exported

| `--types` value | Read with | Model mode (YAML) | `--hcl` mode (plain Terraform) |
|---|---|---|---|
| `roles` | `list-roles`, `get-role` | rules, management-plane access (decoded from `search-rule`/`reports-rule`... `/*`=all, `/self`=own, `/scoped`=scoped), associations + sub-claims | `akeyless_role`, `akeyless_associate_role_auth_method` |
| `auth-methods` | `list-auth-methods`, `get-auth-method` | full settings for OIDC, SAML, OAuth2/JWT, AWS IAM, Azure AD, K8s, Universal Identity, API key, plus bound IPs, JWT TTL, claims... | the above + GCP, LDAP, certificate, OCI, AliCloud, Kerberos, email |
| `folders` | `list-items` walk + `folder get` | explicit folders (description, tags, delete protection) | `akeyless_folder` |
| `custom-fields` | `account-custom-field list` | `governance.yaml custom_fields` | `akeyless_account_custom_field` |
| `key-policies` | `policy list` | `governance.yaml key_policies` | `akeyless_policy_keys` |
| `pki-issuers` | `list-items` walk + `describe-item` | reported (use `--hcl`) | `akeyless_pki_cert_issuer` |
| `account-settings` | `get-account-settings` | saved to raw/ (use `--hcl`) | `akeyless_account_settings` |
| `targets` | `list-targets` | reported (use `--hcl`) | `akeyless_target_*` (type mapping: confirmed for aws, azure, gcp, k8s, hashi_vault; others by name, VERIFY) |
| `groups` | `list-groups` (`/list-group`) | reported (use `--hcl`) | `akeyless_group` |
| `gateway` (not in the default set) | `gateway-get-config` | reported (use `--hcl`) | `akeyless_gateway_defaults`, `_cache`, `_remote_access`, `_log_forwarding_<type>`, `_migration_<type>`, `_allowed_access` (with `provider = akeyless.gateway`) |

Not exported: secret values, keys, rotated/dynamic secret definitions, event forwarders (no list
operation).

## Transport: CLI or REST

`--transport cli` (default) runs the `akeyless` CLI with `--profile` (SSO logins work).
`--transport api` calls the REST API directly with `--token` / `$AKEYLESS_TOKEN`, with no binary
needed. Both read the same operations and produce identical output (tested). See
[api-vs-cli.md](api-vs-cli.md). Gateway reads need `--gateway-url https://gw:8000` (CLI) or
`--gateway-api https://gw:8000/api/v2` (REST).

The auth-method field mapping (e.g. Azure `bound_service_principal_ids` -> `bound_spid`, AWS
`account_id` -> `bound_aws_account_id`) was taken from the provider 2.0.5 read code of every
`akeyless_auth_method_*` resource.

## Two modes

**Model mode (default)**: for this repository's data-driven Terraform.
```bash
scripts/watchover export --out export/ --profile admin \
  --exclude '^/governance/roles/platform/terraform-' --exclude '^/governance/auth/ci-terraform$'
```
Writes `model/roles/imported.yaml`, `model/auth_methods.imported.yaml`, `model/folders.imported.yaml`,
`model/governance.imported.yaml` and `imports.tf` with the `for_each` addresses of `terraform/*.tf`.

**HCL mode**: plain Terraform written by Terraform itself, for anything, including PKI issuers,
account settings and auth-method types the YAML model doesn't cover.
```bash
export AKEYLESS_ACCESS_ID=p-... AKEYLESS_ACCESS_KEY=...       # read-only identity; provider env login
scripts/watchover export --out export/ --profile admin --hcl --generate
```
Writes `hcl/providers.tf` and `hcl/imports.tf` (one flat import block per object). With
`--generate` it then runs `terraform init` and `terraform plan -generate-config-out=generated.tf`:
the provider reads every object and Terraform writes its `resource` blocks into
`hcl/generated.tf`. Without `--generate`, run those two commands yourself in `hcl/`.

## Filters

| Need | Flags |
|---|---|
| Only some families | `--types roles,auth-methods` |
| Only some names | `--only 'sso|payments'`, `--exclude REGEX` (repeatable) |
| Part of the folder tree | `--root /payments --max-depth 5` |
| **One user's view**: their auth method and every role they reach | `--persona-auth-method /governance/auth/sso-entra-oidc --persona-claim email=alice@example.com --persona-claim groups=grp-akl-payments-admins` |
| Offline replay | `--from-dir export/raw` (raw/ of an earlier export) |

The persona view uses the same sub-claim rules as the simulator (OR within a key, AND across keys,
globs, case sensitivity per association). An auth method is configured per identity provider,
not per user: "the OIDC config for a user" is the OIDC auth method plus the associations whose
sub-claims match that user's claims.

## Secrets

* Exported files never contain secrets. In `raw/`, `client_secret`, access keys, passwords,
  private keys and tokens are replaced with `<redacted>`.
* OIDC auth methods get a `client_secret_var`, which you fill in `TF_VAR_auth_method_secrets`.
* In `generated.tf`, Terraform can't read back sensitive values. Replace those with variables
  before applying.
* After import, the state holds what the provider reads (e.g. API-key access keys). Treat the
  state as secret.

## Procedure

1. Run the export and read `REPORT.md`. It lists everything that needs a decision: temporary rules
   (skipped), unknown rule types, root-scope roles, unsupported auth-method types, associations to
   objects outside the export, OIDC secrets to provide, issuers and settings that need `--hcl`.
2. Model mode: move the files into `terraform/model/` (merge with existing files, drop `.imported`)
   and copy `imports.tf` into `terraform/`. HCL mode: review `generated.tf`, then either keep the
   plain resources in their own state, or move them into the YAML model.
3. Run `terraform plan` until it shows **only imports**, with no create, destroy or replace. Then apply.
4. Delete `imports.tf`.

**VERIFY**:
* How `list-items` reports nested folders. The walk is breadth-first and bounded by `--max-depth`.
* Which `item_type` the API uses for PKI issuers. An item counts as an issuer when it has
  `pki_cert_issuer_details`, or when its type contains both PKI and ISSUER. `REPORT.md` lists
  the item types seen.
* That `import` blocks can't be exercised against a mocked provider (an OpenTofu limitation):
  in this repository they are validated, and their model plans are tested without them.
