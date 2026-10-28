# From a structural diagram to Akeyless configuration

## Method (always produce these five artifacts)

1. **Inventory** from the diagram: tenants/BUs, applications, environments, data classes
   (PCI, break-glass), personas (workload, dev team, platform admin, auditor, SecOps,
   certificate requester) and the identity source of each persona.
2. **Path tree** for items.
3. **Access matrix**: personas x path scopes -> capabilities (+ rule type).
4. **YAML model diff** (`terraform/model/...`) and **access expectations**
   (`access_expectations.yaml`).
5. **Plan expectations** and the equivalent **CLI** for break-glass/bootstrap.

Ask before guessing when the diagram does not say who the identity source is, how environments are
segregated, who may change RBAC, or who owns break-glass.

## Path rules

* Delegation boundary first, then the dimensions you grant on, most specific last:
  `/<bu>/<app>/<env>/<class>/<secret>`, e.g. `/payments/checkout/prod/db/orders-ro`.
* If environment is the primary security boundary (separate prod operators):
  `/<env>/<bu>/<app>/...`. Cross-cut the other dimension with `+` (`/payments/+/prod/*`).
* Reserve top-level namespaces: `/shared`, `/pki/{ca,issuers,certs}`, `/platform`.
* Only auditors (list) and admins get `/*`; the guards enforce it (`allow_root_scope`).
* Stable identifiers only (app IDs, not team or person names): renames destroy and recreate
  objects in Terraform and break consumer paths.
* Carve-outs (`break-glass`, `pci`) as a fixed segment so one `deny` covers them.

## Naming of governance objects

| Object | Pattern (enforced by `var.naming`) |
|---|---|
| Roles | `/governance/roles/<bu>/<role>` |
| Auth methods | `/governance/auth/<idp-or-platform>-<scope>` |
| Targets | `/targets/<bu>/<app>/<env>/<name>` |
| Issuers / CA keys | `/pki/issuers/<name>`, `/pki/ca/<name>` |
| Event forwarders | `/governance/events/<name>` |

## Role catalogue

| Role | Rules | Binding |
|---|---|---|
| `<bu>/<app>-<env>-workload` | item read,list on `/<bu>/<app>/<env>/*`; deny on carve-outs | cloud/K8s auth method bound to the workload |
| `<bu>/team-admin` | item CRUD on nonprod, read,list on prod, deny carve-outs | SSO + `groups=<idp-group>` |
| `<bu>/delegated-admin` (optional) | item CRUD on `/<bu>/*`; target CRUD on `/targets/<bu>/*` | SSO group; RBAC changes stay in the pipeline |
| `platform/auditors` | item list `/*`; role/auth-method read,list `/*`; `audit_access=all` | SSO group |
| `platform/pki-requesters-<x>` | rule on the issuer + its `destination_path` | workload or SSO |
| `platform/breakglass` | admin-equivalent | MFA SSO group, alert on use |

**Admin plane:** only the pipeline identity holds create/update/delete on `role-rule` and
`auth-method-rule`. Humans get read,list on those plus `audit_access`.

## Worked example

Diagram: *"Payments BU owns apps checkout and refunds, each with prod and nonprod. Payments engineers
(Entra group grp-akl-payments-admins) manage nonprod and read prod. Checkout prod pods (namespace
payments, SA payments-api) and the checkout Lambda role (payments-app, account 123456789012) read
checkout prod. Nobody but break-glass may read prod/break-glass. Auditors see everything but no
values."*

Path tree:
```
/payments/checkout/{prod,nonprod}/...
/payments/refunds/{prod,nonprod}/...
/payments/+/prod/break-glass/...   (carve-out)
```

Access matrix:

| Persona | `/payments/+/nonprod/*` | `/payments/checkout/prod/*` | `/payments/+/prod/break-glass/*` | roles/auth config |
|---|---|---|---|---|
| payments engineer | CRUD | read | **deny** | - |
| checkout prod workload | - | read | **deny** | - |
| auditor | list | list | list | read |

Model: exactly `terraform/model/roles/payments.yaml` and `platform.yaml` in this repository; the
expectations in `terraform/model/access_expectations.yaml` encode the matrix and run on every PR.
