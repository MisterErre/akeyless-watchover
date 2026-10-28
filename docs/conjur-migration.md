# CyberArk Conjur -> Akeyless

Two separate problems:

| What | How |
|---|---|
| **Secret values** | Akeyless Gateway *Automatic Migration*, type `conjur` (static secrets only): `gateway.yaml -> migrations.conjur` (`akeyless_gateway_migration_conjur`) or `akeyless gateway-create-migration --type conjur ...`. Needs a Conjur identity that can read every variable; private CA -> make the bundle available on the Gateway and set `CONJUR_SSL_CERT_PATH`. |
| **Authorization** (policies, hosts, layers, groups, permits, grants) | Not migrated by Akeyless. `scripts/conjur2akeyless.py` translates Conjur policy YAML into model roles + a bindings report. |

## Translation rules

| Conjur | Akeyless model |
|---|---|
| `!variable <policy>/<id>` | item `<item-prefix>/<policy>/<id>` |
| `execute` (fetch value) | `read` (+ `list`) |
| `read` (see metadata) | `list` |
| `update` (set value) | `update` (+ `list`) |
| a role with permits (layer, group, host, user, policy) | one role `<role-prefix>conjur/<kind>-<id>` with exact-path rules |
| `!grant role: A, member: B` | Akeyless has no role nesting -> B is bound to A's role too (transitive) |
| host / user identities | `bindings.yaml`: Akeyless roles each identity needs; you choose auth method + sub-claims |
| `!webservice`, `!deny`, `!revoke`, `!delete`, permits on non-variables | reported in `REPORT.md`, not translated |

Anchored statement groups (`- &variables [ !variable a, ... ]` with `resources: *variables`) are
supported. Annotations are ignored.

```bash
python3 scripts/conjur2akeyless.py root.yml prod.yml --item-prefix /conjur --role-prefix /governance/roles/ --out export/conjur
```

Mapping Conjur authenticators to Akeyless auth methods (decide per identity in `bindings.yaml`):

| Conjur authenticator | Akeyless auth method | Typical sub-claims |
|---|---|---|
| authn-jwt (CI, GitHub/GitLab) | OAuth2/JWT | `repository`, `ref` / `project_path` |
| authn-k8s | Kubernetes | via Gateway K8s auth config; `bound_namespaces`, `bound_sa_names` |
| authn-iam | AWS IAM | `bound_aws_account_id`, `bound_role_name` |
| authn-azure | Azure AD | `bound_tenant_id`, `bound_spid` |
| authn-oidc / LDAP (humans) | OIDC / SAML / LDAP | `groups` |
| API key hosts | API key or Universal Identity (prefer an identity-based method) | - |

Procedure: translate -> fill bindings as `associations` -> move `roles/conjur.yaml` into
`terraform/model/roles/` -> tests + plan -> run the Gateway migration into the same prefix ->
compare migrated item names with the generated rule paths (**VERIFY** the naming the migration
produces) -> cut consumers over -> decommission Conjur policy.
