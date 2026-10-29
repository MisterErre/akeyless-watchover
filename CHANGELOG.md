# Changelog

## 1.2.0 - 2026-10-29

Added
- `watchover export` reads every exportable object family: roles, auth methods (all types), explicit folders, custom fields, key policies, PKI issuers and account settings.
- Model mode now translates type-specific auth method settings: OIDC (issuer, client ID, redirect URIs, scopes...), SAML, OAuth2/JWT, AWS IAM, Azure AD, K8s and Universal Identity. The field mapping comes from the provider's read code. Model mode also covers folders, custom fields and key policies.
- `--hcl` mode writes flat import blocks for every object. With `--generate` it runs `terraform plan -generate-config-out` so Terraform writes plain HCL itself. This includes PKI issuers, account settings and the GCP/LDAP/cert/OCI/AliCloud/Kerberos/email auth methods.
- Filters: `--types`, `--only`, `--exclude`, `--root`, `--max-depth`, and a persona view (`--persona-auth-method` plus `--persona-claim`) that exports one user's auth method and the roles they reach.
- Secrets are redacted in `raw/`, and `raw/` can be replayed offline with `--from-dir`.

Fixed
- `naming` prefixes are now disabled with `""`. `null` falls back to the default because of `optional(string, default)`, so the old documented way did not work. A test covers it.

## 1.1.0 - 2026-10-28

Added
- `scripts/watchover`: one entry point for every kit command (`test`, `simulate`, `verify`, `export`, `conjur`, `account-settings`, `token`, `build-skill`, `help`, `version`).
- `watchover help`: overview, per-command parameters and examples (`help <command>`), skill commands (`help skill`) and the full guide (`help --markdown`).
- Skill commands with a `help` command: `help`, `design`, `change`, `review`, `pipeline`, `import`, `conjur`, `pki`, `harden`, `gateway`, `verify`, `cli`, `explain`.
- `docs/usage-guide.md`, generated from `scripts/watchover.py`. Tests fail when the guide, SKILL.md or any parameter's help text drift from the code.

Changed
- Every script parameter now has a help text. Scripts expose `build_parser()` and `main(argv)`.

## 1.0.0 - 2026-10-28

First release as **akeyless-watchover**. It was previously drafted as `akeyless-governance-iac`.

Added: closes the gaps identified in the first review.
- Gateway admin plane: `gateway.yaml` -> `akeyless_gateway_allowed_access` (provider alias `akeyless.gateway`).
- SIEM log forwarding (syslog, splunk) and Conjur secret migration on the Gateway.
- CI identity bootstrap (`bootstrap/`): OAuth2/JWT auth method for GitHub or GitLab OIDC, separate plan and apply roles, separate state.
- GitHub Actions and GitLab CI templates with plan, apply, CLI account settings and nightly drift detection. CODEOWNERS example.
- Extended guards: naming prefixes, capabilities per rule type, SRA conflict, root scope, management-plane values, mandatory sub-claims, PKI consistency, event forwarders, gateway objects. Each one is proven by a fixture and by `guard_messages.sh`.
- Governance objects: account custom fields, key policies, event forwarders (email/webhook/slack/teams), account settings (Terraform subset plus the CLI-only part via `akl_account_settings.py`).
- Model-driven PKI: CA keys and issuers.
- Access verification: offline simulator (`akl_simulate.py`) and live verifier (`akl_verify.py`, uses `describe-permissions`).
- Brownfield exporter (`akl_export.py`): YAML model, import blocks and review report.
- Conjur policy translator (`conjur2akeyless.py`).
- Skill packaging (`build_skill.sh`) and repository CI on Terraform and OpenTofu.
- Full documentation in `docs/`.

Fixed:
- `describe-permissions` is documented correctly: it returns the caller's own permissions. The first draft described it as "who can access".
