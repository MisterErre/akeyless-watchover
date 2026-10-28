############################################
# Inputs
############################################
variable "model_dir" {
  description = "Directory (relative to the root module) holding the YAML model."
  type        = string
  default     = "model"
}

variable "auth_method_secrets" {
  description = "Secrets referenced by *_var keys in model/auth_methods.yaml (e.g. OIDC client secrets). Inject from CI, never commit."
  type        = map(string)
  sensitive   = true
  default     = {}
}

variable "event_forwarder_secrets" {
  description = "Secrets referenced by *_var keys in model/governance.yaml event_forwarders (webhook passwords/tokens, Slack/Teams URLs)."
  type        = map(string)
  sensitive   = true
  default     = {}
}

variable "gateway_secrets" {
  description = "Secrets referenced by *_var keys in model/gateway.yaml (e.g. Splunk token)."
  type        = map(string)
  sensitive   = true
  default     = {}
}

variable "naming" {
  description = "Naming policy enforced by the guards. Set a prefix to null to disable that check."
  type = object({
    role_prefix        = optional(string, "/governance/roles/")
    auth_method_prefix = optional(string, "/governance/auth/")
  })
  default = {}
}

variable "allow_ara_rules" {
  description = "Allow rule type ara-rule. Not documented by provider 2.0.5 - enable only after verifying on your account."
  type        = bool
  default     = false
}

############################################
# 1. Load the declarative model (single source of truth)
############################################
locals {
  model_dir   = "${path.root}/${var.model_dir}"
  gateway_api = var.gateway_api == "" ? null : var.gateway_api # CI variables arrive as "" when unset

  auth_methods = try(yamldecode(file("${local.model_dir}/auth_methods.yaml")).auth_methods, {})
  folders      = try(yamldecode(file("${local.model_dir}/folders.yaml")).folders, {})
  governance   = try(yamldecode(file("${local.model_dir}/governance.yaml")), {})
  pki          = try(yamldecode(file("${local.model_dir}/pki.yaml")), {})
  gateway      = try(yamldecode(file("${local.model_dir}/gateway.yaml")), {})

  role_files = sort(fileset("${local.model_dir}/roles", "*.yaml"))
  role_docs  = [for f in local.role_files : try(yamldecode(file("${local.model_dir}/roles/${f}")).roles, {})]
  roles      = merge(local.role_docs...)

  custom_fields     = try(local.governance.custom_fields, {})
  key_policies      = try(local.governance.key_policies, {})
  event_forwarders  = try(local.governance.event_forwarders, {})
  account_settings  = try(local.governance.account_settings, {})
  ca_keys           = try(local.pki.ca_keys, {})
  issuers           = try(local.pki.issuers, {})
  gw_allowed_access = try(local.gateway.allowed_access, {})
  gw_log_forwarding = try(local.gateway.log_forwarding, null)

  # Auth methods split per provider resource type
  am_types = ["api_key", "oidc", "saml", "oauth2", "aws_iam", "azure_ad", "k8s", "universal_identity"]
  am_by_type = {
    for t in local.am_types :
    t => { for n, a in local.auth_methods : n => a if try(a.type, "") == t }
  }

  # Role -> auth method associations, one resource per (role, auth method)
  associations = {
    for a in flatten([
      for rn, r in local.roles : [
        for as in try(r.associations, []) : {
          key            = "${rn}|${as.auth_method}"
          role           = rn
          auth_method    = as.auth_method
          case_sensitive = tostring(try(as.case_sensitive, true))
          # YAML list values become comma-separated (= OR within a key); keys are ANDed
          sub_claims = { for k, v in try(as.sub_claims, {}) : k => try(join(",", v), tostring(v)) }
        }
      ]
    ]) : a.key => a
  }

  all_rules = flatten([for rn, r in local.roles : [for ru in try(r.rules, []) : merge(ru, {
    role = rn
    type = try(ru.type, "item-rule")
  })]])

  # Allowed values (provider 2.0.5 / API docs)
  rule_types        = concat(["item-rule", "target-rule", "role-rule", "auth-method-rule", "sra-rule"], var.allow_ara_rules ? ["ara-rule"] : [])
  crud_capabilities = ["read", "list", "create", "update", "delete", "deny"]
  sra_capabilities  = ["allow_access", "request_access", "justify_access_only", "approval_authority", "upload_files", "download_files"]
  ara_capabilities  = ["allow_access"]
  mgmt_values = {
    audit_access            = ["none", "own", "scoped", "all"]
    analytics_access        = ["none", "own", "all"]
    gw_analytics_access     = ["none", "scoped", "all"]
    sra_reports_access      = ["none", "scoped", "all"]
    event_center_access     = ["none", "scoped", "all"]
    isi_access              = ["none", "scoped", "all"]
    unlock_secrets          = ["none", "scoped", "all"]
    approve_access_request  = ["none", "scoped", "all"]
    usage_reports_access    = ["none", "all"]
    event_forwarders_access = ["none", "all"]
    reverse_rbac_access     = ["scoped", "all"]
  }
  gateway_permissions = ["defaults", "targets", "classic_keys", "automatic_migration", "ldap_auth", "dynamic_secret", "k8s_auth", "log_forwarding", "zero_knowledge_encryption", "rotated_secret", "caching", "event_forwarding", "admin", "kmip", "general", "rotate_secret_value"]
  event_types         = ["request-access", "certificate-pending-expiration", "certificate-expired", "certificate-provisioning-success", "certificate-provisioning-failure", "auth-method-pending-expiration", "auth-method-expired", "next-automatic-rotation", "rotated-secret-success", "rotated-secret-failure", "dynamic-secret-failure", "multi-auth-failure", "uid-rotation-failure", "apply-justification", "email-auth-method-approved", "usage", "rotation-usage", "gateway-inactive", "static-secret-updated", "rate-limiting", "usage-report", "secret-sync"]
  forwarder_types     = ["email", "webhook", "slack", "teams"]
  custom_field_types  = ["STATIC_SECRET", "DYNAMIC_SECRET", "ROTATED_SECRET"]

  object_names = concat(keys(local.roles), keys(local.auth_methods), keys(local.folders), keys(local.ca_keys), keys(local.issuers))
}

############################################
# 2. Model integrity guards (fail the plan, not the apply)
############################################
resource "terraform_data" "model_guards" {
  input = sha256(jsonencode([local.roles, local.auth_methods, local.folders, local.governance, local.pki, local.gateway]))

  lifecycle {
    # --- structure ---
    precondition {
      condition     = length(local.roles) == sum(concat([0], [for d in local.role_docs : length(d)]))
      error_message = "Duplicate role name across model/roles/*.yaml files."
    }
    precondition {
      condition     = alltrue([for n in local.object_names : startswith(n, "/") && !endswith(n, "/")])
      error_message = "Object names must be absolute (leading '/') and must not end with '/'."
    }
    precondition {
      condition     = var.naming.role_prefix == null || alltrue([for n in keys(local.roles) : startswith(n, var.naming.role_prefix)])
      error_message = "Role names must start with the configured naming.role_prefix."
    }
    precondition {
      condition     = var.naming.auth_method_prefix == null || alltrue([for n in keys(local.auth_methods) : startswith(n, var.naming.auth_method_prefix)])
      error_message = "Auth method names must start with the configured naming.auth_method_prefix."
    }
    precondition {
      condition     = alltrue([for n, a in local.auth_methods : contains(local.am_types, try(a.type, ""))])
      error_message = "Unknown auth method type. Supported by this module: api_key, oidc, saml, oauth2, aws_iam, azure_ad, k8s, universal_identity."
    }

    # --- rules ---
    precondition {
      condition     = alltrue([for ru in local.all_rules : contains(local.rule_types, ru.type)])
      error_message = "Unsupported rule type. Allowed: item-rule, target-rule, role-rule, auth-method-rule, sra-rule (ara-rule only with allow_ara_rules = true)."
    }
    precondition {
      condition = alltrue([for ru in local.all_rules : length(setsubtract(ru.capabilities,
        ru.type == "sra-rule" ? local.sra_capabilities : (ru.type == "ara-rule" ? local.ara_capabilities : local.crud_capabilities)
      )) == 0])
      error_message = "Invalid capability for the rule type (CRUD types: read, list, create, update, delete, deny; sra-rule: allow_access, request_access, justify_access_only, approval_authority, upload_files, download_files; ara-rule: allow_access)."
    }
    precondition {
      condition     = alltrue([for ru in local.all_rules : !contains(ru.capabilities, "deny") || length(ru.capabilities) == 1])
      error_message = "A deny rule must contain only 'deny' (deny overrides everything on that path)."
    }
    precondition {
      condition     = alltrue([for ru in local.all_rules : ru.type != "sra-rule" || !(contains(ru.capabilities, "approval_authority") && contains(ru.capabilities, "request_access"))])
      error_message = "sra-rule: approval_authority cannot be combined with request_access."
    }
    precondition {
      condition = alltrue([for ru in local.all_rules :
        !contains(["/*", "/"], ru.path) || try(local.roles[ru.role].allow_root_scope, false) ||
        length(setsubtract(ru.capabilities, contains(["role-rule", "auth-method-rule"], ru.type) ? ["list", "read", "deny"] : ["list", "deny"])) == 0
      ])
      error_message = "Root-scope rule (path '/*') beyond list/deny (or read on role-rule/auth-method-rule) requires 'allow_root_scope: true' on the role."
    }
    precondition {
      condition = alltrue(flatten([for rn, r in local.roles : [for attr, allowed in local.mgmt_values :
        try(r[attr], null) == null || contains(allowed, try(r[attr], ""))
      ]]))
      error_message = "Invalid management-plane value on a role (see local.mgmt_values for the allowed values per attribute)."
    }

    # --- associations ---
    precondition {
      condition = alltrue([for k, a in local.associations :
      contains(keys(local.auth_methods), a.auth_method) || try(local.roles[a.role].allow_external_auth_methods, false)])
      error_message = "Association references an auth method that is not in model/auth_methods.yaml (set allow_external_auth_methods: true on the role to permit)."
    }
    precondition {
      condition = alltrue([for k, a in local.associations :
      !try(local.auth_methods[a.auth_method].force_sub_claims, false) || length(a.sub_claims) > 0])
      error_message = "Auth method has force_sub_claims = true: every association to it must define sub_claims."
    }

    # --- PKI ---
    precondition {
      condition     = alltrue([for n, i in local.issuers : (try(i.signer_key_name, null) == null) != (try(i.ca_target, null) == null)])
      error_message = "PKI issuer: set exactly one of signer_key_name (private CA) or ca_target (public CA)."
    }
    precondition {
      condition     = alltrue([for n, i in local.issuers : !try(i.auto_renew, false) || try(i.destination_path, null) != null])
      error_message = "PKI issuer: auto_renew requires destination_path."
    }
    precondition {
      condition = alltrue([for n, i in local.issuers :
        !(try(i.create_private_crl, false) || try(i.create_private_ocsp, false) || try(i.enable_acme, false) || try(i.ca_target, null) != null) || try(i.gw_cluster_url, null) != null
      ])
      error_message = "PKI issuer: create_private_crl, create_private_ocsp, enable_acme and ca_target require gw_cluster_url."
    }

    # --- governance objects ---
    precondition {
      condition     = alltrue([for n, f in local.custom_fields : contains(local.custom_field_types, try(f.object_type, ""))])
      error_message = "custom_fields.object_type must be STATIC_SECRET, DYNAMIC_SECRET or ROTATED_SECRET."
    }
    precondition {
      condition = alltrue([for n, f in local.event_forwarders :
      contains(local.forwarder_types, try(f.type, "")) && length(setsubtract(try(f.event_types, []), local.event_types)) == 0])
      error_message = "event_forwarders: type must be email|webhook|slack|teams and event_types must be valid Akeyless event types."
    }
    precondition {
      condition     = alltrue([for n, f in local.event_forwarders : try(f.type, "") != "teams" || (length(try(f.gateway_event_source_locations, [])) > 0 && try(f.runner_type, null) != null)])
      error_message = "event_forwarders of type teams require gateway_event_source_locations and runner_type (provider 2.0.5)."
    }

    # --- gateway ---
    precondition {
      condition     = (length(local.gw_allowed_access) == 0 && local.gw_log_forwarding == null && length(try(local.gateway.migrations.conjur, {})) == 0) || local.gateway_api != null
      error_message = "model/gateway.yaml defines gateway objects but var.gateway_api is not set."
    }
    precondition {
      condition     = alltrue([for n, g in local.gw_allowed_access : length(setsubtract(g.permissions, local.gateway_permissions)) == 0])
      error_message = "gateway allowed_access: unknown permission."
    }
    precondition {
      condition     = alltrue([for n, g in local.gw_allowed_access : (try(g.auth_method, null) == null) != (try(g.access_id, null) == null)])
      error_message = "gateway allowed_access: set exactly one of auth_method (managed name) or access_id."
    }
    precondition {
      condition     = local.gw_log_forwarding == null || contains(["syslog", "splunk"], try(local.gw_log_forwarding.type, ""))
      error_message = "gateway log_forwarding.type must be syslog or splunk (other targets: add a resource block)."
    }
  }
}

############################################
# 3. Folders (optional: folders are implicit in item paths; declare to pin
#    delete protection, tags, descriptions or to pre-create empty trees)
############################################
resource "akeyless_folder" "this" {
  for_each          = local.folders
  name              = each.key
  description       = try(each.value.description, null)
  delete_protection = try(tostring(each.value.delete_protection), null)
  tags              = try(each.value.tags, null)

  depends_on = [terraform_data.model_guards]
}
