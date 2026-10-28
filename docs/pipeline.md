# Pipeline: bootstrap, CI/CD, drift and state

## 1. Bootstrap (once, by an Akeyless admin)

```bash
cd bootstrap
cp bootstrap.tfvars.example bootstrap.tfvars          # platform, repository, gitlab_url...
export AKEYLESS_ACCESS_ID=... AKEYLESS_ACCESS_KEY=... # admin API key (provider env fallback)
terraform init && terraform apply -var-file=bootstrap.tfvars
terraform output pipeline_access_id                    # -> CI variable AKEYLESS_PIPELINE_ACCESS_ID
```
Creates:

* OAuth2/JWT auth method `/governance/auth/ci-terraform` trusting GitHub Actions
  (`https://token.actions.githubusercontent.com`) or your GitLab (`<gitlab>/oauth/discovery/keys`),
  `force_sub_claims = true`, audience `akeyless`.
* `.../terraform-plan` role bound with `repository` (GitHub) / `project_path` (GitLab).
* `.../terraform-apply` role bound with repository **and** `ref=refs/heads/main` (GitHub) or
  `ref=main` + `ref_protected=true` (GitLab).

Keep bootstrap state separate and locked down. Delete the admin API key afterwards or keep it as
break-glass in your PAM vault. **VERIFY:** the plan role's minimum read rights are not documented;
extend it if a pull-request plan fails with an authorization error.

## 2. CI templates (`ci/`)

| File | Use |
|---|---|
| `ci/github/akeyless-governance.yml` | copy to `.github/workflows/` in your governance repo |
| `ci/gitlab/.gitlab-ci.yml` | copy to the repo root (GitLab) |
| `ci/CODEOWNERS.example` | per-BU ownership of `model/roles/<bu>.yaml` |

Jobs: **checks** (fmt, validate, tests, guard messages, simulator, script tests) -> **plan** on
pull/merge requests -> **apply** on the default branch behind a protected environment, followed by
`akl_account_settings.py` -> **drift** nightly (`plan -detailed-exitcode`, exit 2 = drift -> job fails).

Tokens: GitHub requests an OIDC token (`id-token: write`, audience `akeyless`); GitLab uses
`id_tokens` with `aud: akeyless`. Terraform receives it as `TF_VAR_pipeline_jwt`; the CLI step
exchanges it for an Akeyless token with `scripts/akl_ci_token.sh` (REST `POST /auth`,
`access-type=jwt`) and passes `--token`.

Variables: `AKEYLESS_PIPELINE_ACCESS_ID`, optional `AKEYLESS_API`, `AKEYLESS_GATEWAY_API`, and the
JSON maps `TF_VAR_auth_method_secrets`, `TF_VAR_event_forwarder_secrets`, `TF_VAR_gateway_secrets`
(secrets/masked). Add your backend configuration.

## 3. State

Remote, encrypted, versioned, access-restricted. It contains API-key access keys, OIDC client
secrets, K8s auth private keys, event-forwarder/webhook secrets, Splunk tokens and the Conjur API
key (provider 2.0.5 has no write-only arguments). Treat the state bucket like a vault.

## 4. Drift

Because role rules are authoritative, console edits show up in the nightly plan and are reverted
by the next apply. Tell administrators: "change Akeyless through a merge request; console changes
are temporary". Emergency changes: make them, then raise the MR that codifies them.
