# The Akeyless authorization model

Verified against docs.akeyless.io (RBAC, Sub-Claims, CLI reference), the Akeyless OpenAPI and the
Terraform provider v2.0.5. Items marked **VERIFY** are not confirmed by a primary source.

## Objects and namespaces

* **Items** (static/rotated/dynamic secrets, keys, certificates, PKI/SSH issuers), **Targets**,
  **Access Roles** and **Auth Methods** live in separate trees, each named by a slash path.
* Item folders are implicit: creating `/a/b/c` creates `/a` and `/a/b`. `folder create` /
  `akeyless_folder` only adds empty folders, description, tags and delete protection.

## Identity

* A caller authenticates through an **Auth Method** (API key, OIDC, SAML, LDAP, OAuth2/JWT, AWS IAM,
  Azure AD, GCP, K8s, certificate, Universal Identity, ...). The token carries the claims of that login.
* There are **no RBAC user or group objects**. Human scoping comes from IdP claims (e.g. `groups`).
* Akeyless **Groups** (`create-group`, `akeyless_group`) bundle auth methods for Akeyless
  **OIDC applications** - they are not RBAC groups.

## Access Roles

* **Default deny**: no association, no access. The built-in admin role has full access.
* A role = **rules** + **management-plane settings**; a role is bound to auth methods by
  **associations** that may carry **sub-claims**.

### Rules

| rule_type | governs | capabilities |
|---|---|---|
| `item-rule` (default) | items | `read, list, create, update, delete, deny` |
| `target-rule` | targets | same |
| `role-rule` | access roles | same |
| `auth-method-rule` | auth methods | same |
| `sra-rule` | Secure Remote Access | `allow_access, request_access, justify_access_only, approval_authority, upload_files, download_files` |
| `ara-rule` | Agentic Runtime Authority | `allow_access` (API/CLI; not documented by provider 2.0.5 - VERIFY) |

* Every capability implies `list`.
* `deny` overrides all other permissions on the matched path (docs). Prove cross-role behaviour
  with Impersonate As / `akl_verify.py`. `deny` does **not** apply to SRA paths.
* `approval_authority` cannot be combined with `request_access`.
* Wildcards: `*` at the end (`/payments/*`) or as a prefix (`/payments/devops-*`); `+` = any
  characters within exactly one segment (`/payments/+/prod/*`).
* Templated paths from sub-claims, e.g. `/{{groups}}/{{email}}/*` (the docs show both `{{x}}` and
  `{x}` - VERIFY on your account).
* Temporary rules: `set-role-rule --ttl <minutes>` (CLI/API only).

### Sub-claims (on associations)

* Within one key, comma-separated values = OR; different keys = AND.
* Values accept `*` and `?` globs.
* Keys and values are case-sensitive unless the association sets `case_sensitive=false`.
* Gateway >= 4.19 accepts explicit `AND` / `OR` inside one key's value, evaluated left to right.
* `force_sub_claims=true` on an auth method makes every association to it require sub-claims.
* `akeyless describe-sub-claims` prints the claims of the current token.

### Management-plane settings (role attributes)

| Attribute | Values |
|---|---|
| `audit_access` | none, own, scoped, all |
| `analytics_access` | none, own, all |
| `gw_analytics_access`, `sra_reports_access`, `event_center_access`, `isi_access`, `unlock_secrets`, `approve_access_request` | none, scoped, all |
| `usage_reports_access`, `event_forwarders_access` | none, all (+ `event_forwarders_name`) |
| `reverse_rbac_access` | scoped, all |

"scoped" = objects the caller can list. Internally these are stored as special rules
(`search-rule`, `reports-rule`, ... with paths `/*`, `/self`, `/scoped`).

## Anti-escalation

* A non-admin can only create or change roles that grant capabilities they themselves hold on the path.
* A non-admin creator's own `deny` rules are copied onto roles they create. Terraform exposes them
  as read-only `restricted_rules` and never removes them.
* Consequence: the identity that applies RBAC must hold everything it grants (admin-equivalent).

## Gateway access - the second layer

RBAC decides which **objects** a caller can touch. **Gateway Allowed Access** decides who may
administer a given Gateway and which features (`defaults, targets, classic_keys,
automatic_migration, ldap_auth, dynamic_secret, k8s_auth, log_forwarding,
zero_knowledge_encryption, rotated_secret, caching, event_forwarding, admin, kmip, general,
rotate_secret_value`). Creating rotated/dynamic secrets on a Gateway requires both layers.

## Inspection

* `akeyless describe-permissions --path P --type item|am|role|target` - the **caller's own**
  permissions on P (`client_permissions`).
* `akeyless reverse-rbac --path P --type item|am|role|target|sra|ara` - which auth methods/roles
  reach P.
* Console: account menu -> **Impersonate As** (auth method + sub-claims).
