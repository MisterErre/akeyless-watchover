terraform {
  required_version = ">= 1.7.0" # mock_provider tests: Terraform >= 1.7, OpenTofu >= 1.8
  required_providers {
    akeyless = {
      source  = "akeyless-community/akeyless"
      version = "~> 2.0"
    }
  }
  # backend "s3" / "azurerm" / "gcs" / "remote" { ... }  # remote, encrypted, access-restricted, versioned state
}

variable "akeyless_api" {
  description = "Akeyless API endpoint for control-plane objects: https://api.akeyless.io (default) or a Gateway V2 API."
  type        = string
  default     = "https://api.akeyless.io"
}

variable "gateway_api" {
  description = "Gateway V2 API (https://<gw>:8000/api/v2 or https://<gw>:8081) used for gateway_* resources. null = gateway objects disabled. One Gateway cluster per state/workspace."
  type        = string
  default     = null
}

variable "pipeline_jwt" {
  description = "CI OIDC/JWT token (export TF_VAR_pipeline_jwt in the pipeline)."
  type        = string
  sensitive   = true
}

variable "pipeline_access_id" {
  description = "Access ID of the CI/CD JWT (OAuth2) auth method created by ../bootstrap."
  type        = string
}

provider "akeyless" {
  api_gateway_address = var.akeyless_api
  jwt_login {
    access_id = var.pipeline_access_id
    jwt       = var.pipeline_jwt # must be set explicitly: validate fails without it
  }
}

# Gateway-scoped resources (allowed access, log forwarding) go through the Gateway API.
provider "akeyless" {
  alias               = "gateway"
  api_gateway_address = coalesce(local.gateway_api, var.akeyless_api)
  jwt_login {
    access_id = var.pipeline_access_id
    jwt       = var.pipeline_jwt
  }
}
