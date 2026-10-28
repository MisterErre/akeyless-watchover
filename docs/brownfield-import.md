# Bringing an existing account under code

```bash
python3 scripts/akl_export.py --out export/ --profile admin \
  --exclude '^/governance/roles/platform/terraform-' --exclude '^/governance/auth/ci-terraform$'
```
Reads every role (`list-roles`, `get-role`) and auth method (`list-auth-methods`,
`get-auth-method`) and writes:

| Output | Content |
|---|---|
| `model/roles/imported.yaml` | rules, management-plane attributes (decoded from `search-rule`, `reports-rule`... `/*`=all, `/self`=own, `/scoped`=scoped), associations with sub-claims |
| `model/auth_methods.imported.yaml` | type (from `access_info.rules_type`) + common settings; type-specific settings marked `TODO` |
| `imports.tf` | `import {}` blocks for the exact addresses used by `terraform/` |
| `raw/` | every JSON document read |
| `REPORT.md` | everything needing a decision: temporary rules (skipped), unknown rule types, root-scope rules, unsupported auth method types, associations to excluded auth methods, operator sub-claims |

Procedure:
1. Exclude the bootstrap objects (above).
2. Complete the `TODO` settings from `raw/auth_methods/*.json`.
3. Move files into `terraform/model/` (rename to `auth_methods.yaml` / merge), copy `imports.tf`
   into `terraform/`.
4. `terraform plan` until it shows only imports and **no** create/destroy/replace; then apply.
5. Delete `imports.tf`.

Offline test: `--from-dir saved/` (layout `saved/roles/*.json`, `saved/auth_methods/*.json`).
**VERIFY:** the exact `access_info.rules_type` strings returned by your account; unknown ones are
reported, never guessed.
