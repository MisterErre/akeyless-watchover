# YAML model reference

All files live in `terraform/model/` (override with `var.model_dir`). Every file is optional
except what you use. Object names are absolute paths (leading `/`, no trailing `/`).
Values ending in `_var` are **names of keys** in a sensitive Terraform variable, never secrets.

## `roles/<any>.yaml` - access roles (one file per BU, protected by CODEOWNERS)

```yaml
roles:
  /governance/roles/<bu>/<role>:
    description: text
    delete_protection: true            # optional
    allow_root_scope: false            # required true for '/*' rules beyond list/deny
    allow_external_auth_methods: false # allow associations to auth methods not in auth_methods.yaml
    # management plane (see rbac-model.md for allowed values)
    audit_access: scoped
    analytics_access: own
    gw_analytics_access: none
    sra_reports_access: none
    usage_reports_access: none
    event_center_access: scoped
    event_forwarders_access: none
    event_forwarders_name: [/governance/events/x]
    reverse_rbac_access: scoped
    isi_access: none
    unlock_secrets: none
    approve_access_request: scoped
    rules:                              # AUTHORITATIVE - the full list of the role's rules
      - path: /payments/+/prod/*
        capabilities: [read, list]
        type: item-rule                 # default; target-rule | role-rule | auth-method-rule | sra-rule | ara-rule*
    associations:
      - auth_method: /governance/auth/sso-entra-oidc
        sub_claims:                     # key: string "a,b" or list [a, b]  (OR within a key, AND across keys)
          groups: [grp-akl-payments-admins]
        case_sensitive: true            # default true
```
`*` `ara-rule` only with `-var allow_ara_rules=true`.

## `auth_methods.yaml`

```yaml
auth_methods:
  /governance/auth/<name>:
    type: oidc        # api_key | oidc | saml | oauth2 | aws_iam | azure_ad | k8s | universal_identity
    # common to all types
    description: text
    access_expires: 0             # unix timestamp, 0 = never
    bound_ips: [10.0.0.0/8]
    gw_bound_ips: [10.1.0.0/16]
    force_sub_claims: true        # recommended for shared IdP/CI methods
    jwt_ttl: 60                   # minutes
    audit_logs_claims: [email]
    allowed_client_type: [cli, ui] # cli, ui, gateway-admin, sdk, mobile, extension
    product_type: [sm]            # sm, sra, pm, dp, ca
    expiration_event_in: ["30"]
    delete_protection: true
```
Type-specific keys:

| type | keys |
|---|---|
| oidc | `unique_identifier`*, `issuer`, `client_id`, `client_secret_var`, `audience`, `allowed_redirect_uri`, `required_scopes`, `required_scopes_prefix`, `subclaims_delimiters` |
| saml | `unique_identifier`*, `idp_metadata_url`, `idp_metadata_xml_data`, `allowed_redirect_uri`, `subclaims_delimiters` |
| oauth2 | `unique_identifier`*, `jwks_uri`, `jwks_json_data`, `issuer`, `audience`, `bound_client_ids`, `subclaims_delimiters` |
| aws_iam | `bound_aws_account_id`*, `bound_arn`, `bound_role_name`, `bound_role_id`, `bound_user_name`, `bound_user_id`, `bound_resource_id`, `sts_url` |
| azure_ad | `bound_tenant_id`*, `bound_spid`, `bound_group_id`, `bound_sub_id`, `bound_rg_id`, `bound_resource_id`, `bound_resource_names`, `bound_resource_types`, `bound_providers`, `audience`, `issuer`, `jwks_uri` |
| k8s | `bound_namespaces`, `bound_sa_names`, `bound_pod_names`, `audience`, `gen_key`, `public_key` (also needs a Gateway K8s auth config) |
| universal_identity | `ttl`, `deny_inheritance`, `deny_rotate` |
| api_key | - (the access key ends up in state; prefer identity-based methods) |

`*` = required. The CI identity Terraform runs as is **not** declared here (see `bootstrap/`).

## `folders.yaml`

```yaml
folders:
  /payments:
    description: text
    delete_protection: true
    tags: [bu:payments]
```

## `governance.yaml`

```yaml
custom_fields:                     # mandatory metadata on secrets
  <id>:
    name: owner                    # default: the key
    object_type: STATIC_SECRET     # STATIC_SECRET | DYNAMIC_SECRET | ROTATED_SECRET
    object: <optional>
    required: true

key_policies:
  /payments/*:                     # path
    allowed_algorithms: [AES256GCM, RSA4096]
    allowed_key_types: [dfc]       # dfc, classic-key
    allowed_key_names: []
    max_rotation_interval_days: 365
    object_types: [items]          # items, targets

account_settings:                  # Terraform-managed subset (provider 2.0.5)
  # company_name, default_share_link_ttl_minutes, default_versioning, dynamic_secret_max_ttl,
  # dynamic_secret_max_ttl_enable, enable_ai_quorum, enable_item_sharing, enable_password_expiration,
  # hide_personal_folder, hide_static_password, invalid_characters, item_locking_enabled,
  # items_deletion_protection, jwt_ttl_default, jwt_ttl_max, jwt_ttl_min, max_versions,
  # password_expiration_days, password_expiration_notification_days, password_length,
  # use_capital_letters, use_lower_letters, use_numbers, use_special_characters

account_settings_cli:              # applied by scripts/akl_account_settings.py
  # keys = update-account-settings flags without '--'; lists repeat the flag; bools -> =true/false
  bound-ips: [10.0.0.0/8]
  lock-bound-ips: true

event_forwarders:
  /governance/events/<name>:
    type: email                    # email | webhook | slack | teams | service_now
    event_types: [certificate-pending-expiration, ...]   # validated list, see main.tf
    runner_type: immediate         # immediate | periodic (teams: required)
    every: 24                      # hours, periodic only
    enable: true
    items_event_source_locations: ["/*"]
    targets_event_source_locations: []
    auth_methods_event_source_locations: []
    gateways_event_source_locations: []     # teams uses gateway_event_source_locations (required)
    key: /optional/protection-key
    # email:   email_to (list|string), include_error, override_url
    # webhook: url, auth_type (user-pass|bearer-token|certificate), username, password_var, auth_token_var,
    #          client_cert_data_var, private_key_data_var, server_certificates_var
    # slack:   url_var        teams: url_var
    # service_now: host, auth_type (user-pass|jwt); user-pass: admin_name, admin_pwd_var;
    #          jwt: client_id, user_email, client_secret_var, app_private_key_var
```

`*_var` values are keys of the `event_forwarder_secrets` variable (`TF_VAR_event_forwarder_secrets`, a JSON
map kept in CI secrets); secrets never go in the model. Guards: valid type and event types, `every` with
`runner_type: periodic`, `url_var` for slack/teams, `gateway_event_source_locations` + `runner_type` for teams.

Akeyless has no operation that lists event forwarders, so `watchover export` cannot read them. Write new
ones with `watchover forwarder` (validated entry, `--write` inserts it here, `--format hcl` for plain
Terraform); adopt an existing one whose name you know with `--import-existing` (import ID = name).
Presets: `certificates`, `auth-methods`, `rotation`, `secrets`, `access-requests`, `operations`, `critical`
(see `watchover help forwarder`).

## `pki.yaml`

```yaml
ca_keys:                            # private CA signer keys (DFC RSA, self-signed CA certificate)
  /pki/ca/<name>:
    alg: RSA4096                    # default RSA4096
    certificate_ttl_days: 3650      # required
    path_len: 0                     # optional, adds pathlen to basicConstraints
    subject: { countryName: ES, organizationName: X, commonName: X Root CA }
    delete_protection: true         # default true
issuers:
  /pki/issuers/<name>:
    ttl_seconds: 7776000            # required
    signer_key_name: /pki/ca/<name> # private CA  (exactly one of signer_key_name / ca_target)
    ca_target: /targets/...         # public CA (requires gw_cluster_url)
    gw_cluster_url: https://gw:8000 # required for ca_target, private CRL/OCSP, ACME
    allowed_domains: [a.example.com]
    allowed_uri_sans: []
    allowed_ip_sans: []
    allow_subdomains: true
    allow_any_name: false
    disable_wildcards: false
    not_enforce_hostnames: false
    not_require_cn: false
    server_flag: true
    client_flag: false
    code_signing_flag: false
    key_usage: [DigitalSignature, KeyEncipherment]
    critical_key_usage: true
    organizations: X
    organizational_units: Y
    country: ES
    locality: Madrid
    province: Madrid
    max_path_len: -1
    destination_path: /pki/certs/<x>   # required for auto_renew and CRL
    protect_certificates: true
    auto_renew: true
    scheduled_renew_days: 30
    expiration_event_in_days: [30, 7]
    create_public_crl: false
    create_private_crl: false
    create_public_ocsp: false
    create_private_ocsp: false
    enable_acme: false
    allowed_extra_extensions: { "1.2.3": ["value"] }
    delete_protection: true            # default true
    tags: []
```

## `gateway.yaml` (needs `var.gateway_api`)

```yaml
allowed_access:
  <name>:
    auth_method: /governance/auth/<name>   # or access_id: p-xxxx (exactly one)
    permissions: [admin]                    # validated list, see rbac-model.md
    sub_claims: { groups: [grp-x] }
    case_sensitive: true
    description: text
log_forwarding:                              # singleton per Gateway
  type: syslog                               # syslog | splunk
  # syslog: host*, network (tcp|udp), enable_tls, formatter (text|cef), output_format (text|json), target_tag, pull_interval
  # splunk: splunk_url*, splunk_token_var*, index, source, source_type, enable_tls, enable_batch, output_format, pull_interval
migrations:
  conjur:
    <name>:
      target_location: /conjur
      conjur_url: https://conjur.example.com
      conjur_account: myorg
      conjur_username: host/akeyless-migration
      conjur_api_key_var: conjur_api_key
      protection_key: /optional/key
```

## `access_expectations.yaml`

```yaml
personas:
  <persona>:
    auth_method: /governance/auth/<name>
    claims: { groups: [grp-x], email: [a@b.c] }   # claims the persona's token would carry
    profile: <cli-profile>                          # optional, for live verification
checks:
  - { persona: <persona>, path: /x/y, type: item, expect: [read, list] }  # type: item|target|role|auth-method
```
