# One-time bootstrap, run by an Akeyless admin from a workstation.
# Creates the CI/CD identity the main stack (../terraform) runs as, plus its roles.
# Kept in its own state so the main pipeline can never destroy its own access.
#
#   export AKEYLESS_ACCESS_ID=<admin api-key access id>   # provider falls back to these env vars
#   export AKEYLESS_ACCESS_KEY=<admin api-key access key>  # when no login block is configured
#   terraform init && terraform apply -var-file=bootstrap.tfvars

terraform {
  required_version = ">= 1.7.0"
  required_providers {
    akeyless = {
      source  = "akeyless-community/akeyless"
      version = "~> 2.0"
    }
  }
}

provider "akeyless" {
  api_gateway_address = var.akeyless_api
}

variable "akeyless_api" {
  type    = string
  default = "https://api.akeyless.io"
}

variable "ci" {
  description = "CI system trusted to run Terraform."
  type = object({
    platform     = string                                 # "github" | "gitlab"
    repository   = string                                 # github: org/repo ; gitlab: group/project
    gitlab_url   = optional(string, "https://gitlab.com") # gitlab only
    audience     = optional(string, "akeyless")
    apply_ref    = optional(string, "refs/heads/main") # github: ref claim ; gitlab: branch name, e.g. "main"
    auth_name    = optional(string, "/governance/auth/ci-terraform")
    roles_prefix = optional(string, "/governance/roles/platform/")
  })

  validation {
    condition     = contains(["github", "gitlab"], var.ci.platform)
    error_message = "ci.platform must be github or gitlab."
  }
}

variable "managed_scopes" {
  description = "Paths the apply identity may administer. Keep '/*' unless the account hosts objects that must stay out of reach of this pipeline."
  type = object({
    items        = optional(string, "/*")
    targets      = optional(string, "/*")
    roles        = optional(string, "/*")
    auth_methods = optional(string, "/*")
  })
  default = {}
}

locals {
  is_github = var.ci.platform == "github"
  jwks_uri  = local.is_github ? "https://token.actions.githubusercontent.com/.well-known/jwks" : "${trimsuffix(var.ci.gitlab_url, "/")}/oauth/discovery/keys"
  issuer    = local.is_github ? "https://token.actions.githubusercontent.com" : trimsuffix(var.ci.gitlab_url, "/")
  repo_key  = local.is_github ? "repository" : "project_path"
  # apply: only the protected default branch of the governance repo
  apply_claims = local.is_github ? {
    repository = var.ci.repository
    ref        = var.ci.apply_ref
    } : {
    project_path  = var.ci.repository
    ref           = trimprefix(var.ci.apply_ref, "refs/heads/")
    ref_protected = "true"
  }
  plan_claims = { (local.repo_key) = var.ci.repository }

  crud = ["read", "list", "create", "update", "delete"]
}

resource "akeyless_auth_method_oauth2" "ci" {
  name              = var.ci.auth_name
  description       = "CI/CD identity for the akeyless-governance pipeline (${var.ci.platform}:${var.ci.repository})"
  jwks_uri          = local.jwks_uri
  issuer            = local.issuer
  audience          = var.ci.audience
  unique_identifier = local.repo_key
  force_sub_claims  = true
  jwt_ttl           = 60
  audit_logs_claims = local.is_github ? ["repository", "ref", "actor", "run_id"] : ["project_path", "ref", "user_login", "pipeline_id"]
  delete_protection = "true"
  lifecycle { prevent_destroy = true }
}

# PLAN identity: read-mostly. Can read RBAC/auth config and list items.
# VERIFY: Akeyless does not document the minimum capability for every read the
# provider performs; extend this role if a PR plan fails with "unauthorized".
resource "akeyless_role" "plan" {
  name                = "${var.ci.roles_prefix}terraform-plan"
  description         = "Terraform plan on merge requests (read-mostly)"
  audit_access        = "none"
  reverse_rbac_access = "all"
  rules {
    path       = "/*"
    capability = ["list"]
    rule_type  = "item-rule"
  }
  rules {
    path       = "/pki/*"
    capability = ["read", "list"]
    rule_type  = "item-rule"
  }
  rules {
    path       = "/*"
    capability = ["read", "list"]
    rule_type  = "role-rule"
  }
  rules {
    path       = "/*"
    capability = ["read", "list"]
    rule_type  = "auth-method-rule"
  }
  rules {
    path       = "/*"
    capability = ["list"]
    rule_type  = "target-rule"
  }
  event_forwarders_access = "all"
  delete_protection       = "true"
}

# APPLY identity: must hold every capability it grants (Akeyless anti-escalation).
resource "akeyless_role" "apply" {
  name        = "${var.ci.roles_prefix}terraform-apply"
  description = "Terraform apply from the protected branch only"
  rules {
    path       = var.managed_scopes.items
    capability = local.crud
    rule_type  = "item-rule"
  }
  rules {
    path       = var.managed_scopes.targets
    capability = local.crud
    rule_type  = "target-rule"
  }
  rules {
    path       = var.managed_scopes.roles
    capability = local.crud
    rule_type  = "role-rule"
  }
  rules {
    path       = var.managed_scopes.auth_methods
    capability = local.crud
    rule_type  = "auth-method-rule"
  }
  audit_access            = "all"
  analytics_access        = "all"
  gw_analytics_access     = "all"
  sra_reports_access      = "all"
  usage_reports_access    = "all"
  event_center_access     = "all"
  event_forwarders_access = "all"
  reverse_rbac_access     = "all"
  isi_access              = "all"
  unlock_secrets          = "all"
  approve_access_request  = "all"
  delete_protection       = "true"
}

resource "akeyless_associate_role_auth_method" "plan" {
  role_name      = akeyless_role.plan.name
  am_name        = akeyless_auth_method_oauth2.ci.name
  sub_claims     = local.plan_claims
  case_sensitive = "true"
}

resource "akeyless_associate_role_auth_method" "apply" {
  role_name      = akeyless_role.apply.name
  am_name        = akeyless_auth_method_oauth2.ci.name
  sub_claims     = local.apply_claims
  case_sensitive = "true"
}

output "pipeline_access_id" {
  description = "Set as CI variable AKEYLESS_PIPELINE_ACCESS_ID (not secret)."
  value       = akeyless_auth_method_oauth2.ci.access_id
}
