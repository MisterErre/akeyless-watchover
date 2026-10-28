# CLI playbook

Command style varies by family: `auth-method create <type>`, `target create <type>`,
`rotated-secret create <type>`, `dynamic-secret create <type>`, `folder create`, while roles and PKI
keep hyphenated verbs (`create-role`, `set-role-rule`, `create-pki-cert-issuer`). Older hyphenated
auth forms (`create-auth-method-oidc`) still appear in docs. The installed CLI wins:
`akeyless <command> -h`. Global flags: `--profile`, `--token`, `--uid-token`, `--json`,
`--jq-expression`. Profiles: `~/.akeyless/profiles` (`akeyless configure`). Boolean-like flags are
written `--flag=true`, accepted for bool and `[true/false]` string flags alike.

Install: `curl -o akeyless https://akeyless-cli.s3.us-east-2.amazonaws.com/cli/latest/cli-linux-amd64 && chmod +x akeyless`
(or `brew tap akeylesslabs/tap`).

## RBAC

```bash
akeyless create-role --name /governance/roles/payments/team-admin --description "..." --audit-access scoped
akeyless set-role-rule --role-name /governance/roles/payments/team-admin \
  --path "/payments/+/nonprod/*" --capability read --capability list --capability create --capability update --capability delete
akeyless set-role-rule --role-name /governance/roles/payments/team-admin --path "/payments/+/prod/break-glass/*" --capability deny
akeyless set-role-rule --role-name <role> --path "/governance/roles/*" --rule-type role-rule --capability read --capability list
akeyless set-role-rule --role-name <role> --path "<path>" --capability read --ttl 60   # temporary (minutes)
akeyless delete-role-rule --role-name <role> --path "<path>" --rule-type item-rule
akeyless assoc-role-am --role-name <role> --am-name /governance/auth/sso-entra-oidc \
  --sub-claims groups=grp-akl-payments-admins --case-sensitive=true
akeyless update-assoc --assoc-id <assoc-id> --sub-claims groups=grp-a,grp-b
akeyless delete-assoc --assoc-id <assoc-id>
akeyless get-role --name <role> --json          # rules + associations (assoc IDs)
akeyless list-roles --json
akeyless update-role --name <role> --new-name <new>   # rename (Terraform cannot)
```
Temporary rules on a Terraform-managed role are removed by the next apply (rules are authoritative).
For just-in-time access prefer `request-access` + roles with `approve_access_request`.

## Auth methods

```bash
akeyless auth-method create oidc --name /governance/auth/sso-entra-oidc --issuer <url> \
  --client-id <id> --client-secret <secret> --unique-identifier email --force-sub-claims=true --jwt-ttl 60
akeyless auth-method create oauth2 --name /governance/auth/ci-terraform \
  --jwks-uri https://token.actions.githubusercontent.com/.well-known/jwks --unique-identifier repository
akeyless auth-method create aws-iam --name <n> --bound-aws-account-id <acct> --bound-role-name <role>
akeyless auth-method create azure-ad --name <n> --bound-tenant-id <tenant>
akeyless list-auth-methods --json ; akeyless get-auth-method --name <n> --json
```
Common flags: `--access-expires`, `--bound-ips`, `--gw-bound-ips`, `--force-sub-claims`, `--jwt-ttl`,
`--audit-logs-claims`, `--allowed-client-type`, `--product-type`, `--expiration-event-in`,
`--delete-protection`.

## Inspection

```bash
akeyless describe-permissions --path /payments/checkout/prod/db/app --type item   # MY permissions on the path
akeyless reverse-rbac --path <path> --type item|am|role|target|sra|ara             # who reaches the path
akeyless describe-sub-claims [--profile <p>]
akeyless list-items --path /payments --json
akeyless move-objects --source /old/folder --target /new/folder                    # folders only
```

## Account settings (CLI-only part)

`scripts/akl_account_settings.py` turns `account_settings_cli` in `governance.yaml` into one
idempotent `update-account-settings` call (admin-only). It refuses keys the Terraform resource
manages and unknown flags.

```bash
python3 scripts/akl_account_settings.py --governance terraform/model/governance.yaml --dry-run
AKEYLESS_TOKEN=$(AKEYLESS_ACCESS_ID=p-xxx CI_JWT=$JWT scripts/akl_ci_token.sh) \
  python3 scripts/akl_account_settings.py --governance terraform/model/governance.yaml
```
Test `lock-bound-ips` from a non-allowed network before locking it in production.

## Gateway

```bash
akeyless gateway-create-allowed-access --name pki-admins --access-id <p-xxxx> \
  --sub-claims groups=grp-akl-pki --permissions general,targets --gateway-url 'https://<gw>:8000'
akeyless gateway-create-migration --type conjur --name conjur-prod --target-location /conjur \
  --conjur-url https://conjur --conjur-account myorg --conjur-username <u> --conjur-api-key <k> \
  --gateway-url 'https://<gw>:8000'
```

## PKI

```bash
akeyless create-dfc-key --name /pki/ca/root --alg RSA4096 --generate-self-signed-certificate true \
  --certificate-ttl 3650 --conf-file-path ./csr.conf --certificate-format pem
akeyless create-pki-cert-issuer --name /pki/issuers/x --signer-key-name /pki/ca/root --ttl 30d \
  --destination-path /pki/certs/x --expiration-event-in 30
akeyless get-pki-certificate --cert-issuer-name /pki/issuers/x --csr-file-path ./my.csr --outfile cert.pem
akeyless revoke-certificate --name <cert item> --version <n>
```
