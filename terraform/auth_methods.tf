# One resource block per auth method type. Common governance arguments are
# identical across types (verified against provider 2.0.5 schema).
locals {
  am_common = {
    for n, a in local.auth_methods : n => {
      description         = try(a.description, null)
      access_expires      = try(a.access_expires, null) # unix ts, 0 = never
      bound_ips           = try(a.bound_ips, null)
      gw_bound_ips        = try(a.gw_bound_ips, null)
      force_sub_claims    = try(a.force_sub_claims, null)
      jwt_ttl             = try(a.jwt_ttl, null) # minutes
      audit_logs_claims   = try(a.audit_logs_claims, null)
      allowed_client_type = try(a.allowed_client_type, null) # cli, ui, gateway-admin, sdk, mobile, extension
      product_type        = try(a.product_type, null)        # sm, sra, pm, dp, ca
      expiration_event_in = try(a.expiration_event_in, null)
      delete_protection   = try(tostring(a.delete_protection), null) # string "true"/"false" on auth methods
    }
  }
}

resource "akeyless_auth_method_api_key" "this" {
  for_each            = local.am_by_type["api_key"]
  name                = each.key
  description         = local.am_common[each.key].description
  access_expires      = local.am_common[each.key].access_expires
  bound_ips           = local.am_common[each.key].bound_ips
  gw_bound_ips        = local.am_common[each.key].gw_bound_ips
  force_sub_claims    = local.am_common[each.key].force_sub_claims
  jwt_ttl             = local.am_common[each.key].jwt_ttl
  audit_logs_claims   = local.am_common[each.key].audit_logs_claims
  allowed_client_type = local.am_common[each.key].allowed_client_type
  product_type        = local.am_common[each.key].product_type
  expiration_event_in = local.am_common[each.key].expiration_event_in
  delete_protection   = local.am_common[each.key].delete_protection
  depends_on          = [terraform_data.model_guards]
  lifecycle { prevent_destroy = true } # recreate = new access_id + new access_key
}

resource "akeyless_auth_method_oidc" "this" {
  for_each               = local.am_by_type["oidc"]
  name                   = each.key
  unique_identifier      = each.value.unique_identifier
  issuer                 = try(each.value.issuer, null)
  client_id              = try(each.value.client_id, null)
  client_secret          = try(var.auth_method_secrets[each.value.client_secret_var], null)
  audience               = try(each.value.audience, null)
  allowed_redirect_uri   = try(each.value.allowed_redirect_uri, null)
  required_scopes        = try(each.value.required_scopes, null)
  required_scopes_prefix = try(each.value.required_scopes_prefix, null)
  subclaims_delimiters   = try(each.value.subclaims_delimiters, null)
  description            = local.am_common[each.key].description
  access_expires         = local.am_common[each.key].access_expires
  bound_ips              = local.am_common[each.key].bound_ips
  gw_bound_ips           = local.am_common[each.key].gw_bound_ips
  force_sub_claims       = local.am_common[each.key].force_sub_claims
  jwt_ttl                = local.am_common[each.key].jwt_ttl
  audit_logs_claims      = local.am_common[each.key].audit_logs_claims
  allowed_client_type    = local.am_common[each.key].allowed_client_type
  product_type           = local.am_common[each.key].product_type
  expiration_event_in    = local.am_common[each.key].expiration_event_in
  delete_protection      = local.am_common[each.key].delete_protection
  depends_on             = [terraform_data.model_guards]
  lifecycle { prevent_destroy = true }
}

resource "akeyless_auth_method_saml" "this" {
  for_each              = local.am_by_type["saml"]
  name                  = each.key
  unique_identifier     = each.value.unique_identifier
  idp_metadata_url      = try(each.value.idp_metadata_url, null)
  idp_metadata_xml_data = try(each.value.idp_metadata_xml_data, null)
  allowed_redirect_uri  = try(each.value.allowed_redirect_uri, null)
  subclaims_delimiters  = try(each.value.subclaims_delimiters, null)
  description           = local.am_common[each.key].description
  access_expires        = local.am_common[each.key].access_expires
  bound_ips             = local.am_common[each.key].bound_ips
  gw_bound_ips          = local.am_common[each.key].gw_bound_ips
  force_sub_claims      = local.am_common[each.key].force_sub_claims
  jwt_ttl               = local.am_common[each.key].jwt_ttl
  audit_logs_claims     = local.am_common[each.key].audit_logs_claims
  allowed_client_type   = local.am_common[each.key].allowed_client_type
  product_type          = local.am_common[each.key].product_type
  expiration_event_in   = local.am_common[each.key].expiration_event_in
  delete_protection     = local.am_common[each.key].delete_protection
  depends_on            = [terraform_data.model_guards]
  lifecycle { prevent_destroy = true }
}

resource "akeyless_auth_method_oauth2" "this" {
  for_each             = local.am_by_type["oauth2"]
  name                 = each.key
  unique_identifier    = each.value.unique_identifier
  jwks_uri             = try(each.value.jwks_uri, null)
  jwks_json_data       = try(each.value.jwks_json_data, null)
  issuer               = try(each.value.issuer, null)
  audience             = try(each.value.audience, null)
  bound_client_ids     = try(each.value.bound_client_ids, null)
  subclaims_delimiters = try(each.value.subclaims_delimiters, null)
  description          = local.am_common[each.key].description
  access_expires       = local.am_common[each.key].access_expires
  bound_ips            = local.am_common[each.key].bound_ips
  gw_bound_ips         = local.am_common[each.key].gw_bound_ips
  force_sub_claims     = local.am_common[each.key].force_sub_claims
  jwt_ttl              = local.am_common[each.key].jwt_ttl
  audit_logs_claims    = local.am_common[each.key].audit_logs_claims
  allowed_client_type  = local.am_common[each.key].allowed_client_type
  product_type         = local.am_common[each.key].product_type
  expiration_event_in  = local.am_common[each.key].expiration_event_in
  delete_protection    = local.am_common[each.key].delete_protection
  depends_on           = [terraform_data.model_guards]
  lifecycle { prevent_destroy = true }
}

resource "akeyless_auth_method_aws_iam" "this" {
  for_each             = local.am_by_type["aws_iam"]
  name                 = each.key
  bound_aws_account_id = each.value.bound_aws_account_id
  bound_arn            = try(each.value.bound_arn, null)
  bound_role_name      = try(each.value.bound_role_name, null)
  bound_role_id        = try(each.value.bound_role_id, null)
  bound_user_name      = try(each.value.bound_user_name, null)
  bound_user_id        = try(each.value.bound_user_id, null)
  bound_resource_id    = try(each.value.bound_resource_id, null)
  sts_url              = try(each.value.sts_url, null)
  description          = local.am_common[each.key].description
  access_expires       = local.am_common[each.key].access_expires
  bound_ips            = local.am_common[each.key].bound_ips
  gw_bound_ips         = local.am_common[each.key].gw_bound_ips
  force_sub_claims     = local.am_common[each.key].force_sub_claims
  jwt_ttl              = local.am_common[each.key].jwt_ttl
  audit_logs_claims    = local.am_common[each.key].audit_logs_claims
  allowed_client_type  = local.am_common[each.key].allowed_client_type
  product_type         = local.am_common[each.key].product_type
  expiration_event_in  = local.am_common[each.key].expiration_event_in
  delete_protection    = local.am_common[each.key].delete_protection
  depends_on           = [terraform_data.model_guards]
  lifecycle { prevent_destroy = true }
}

resource "akeyless_auth_method_azure_ad" "this" {
  for_each             = local.am_by_type["azure_ad"]
  name                 = each.key
  bound_tenant_id      = each.value.bound_tenant_id
  bound_spid           = try(each.value.bound_spid, null)
  bound_group_id       = try(each.value.bound_group_id, null)
  bound_sub_id         = try(each.value.bound_sub_id, null)
  bound_rg_id          = try(each.value.bound_rg_id, null)
  bound_resource_id    = try(each.value.bound_resource_id, null)
  bound_resource_names = try(each.value.bound_resource_names, null)
  bound_resource_types = try(each.value.bound_resource_types, null)
  bound_providers      = try(each.value.bound_providers, null)
  audience             = try(each.value.audience, null)
  issuer               = try(each.value.issuer, null)
  jwks_uri             = try(each.value.jwks_uri, null)
  description          = local.am_common[each.key].description
  access_expires       = local.am_common[each.key].access_expires
  bound_ips            = local.am_common[each.key].bound_ips
  gw_bound_ips         = local.am_common[each.key].gw_bound_ips
  force_sub_claims     = local.am_common[each.key].force_sub_claims
  jwt_ttl              = local.am_common[each.key].jwt_ttl
  audit_logs_claims    = local.am_common[each.key].audit_logs_claims
  allowed_client_type  = local.am_common[each.key].allowed_client_type
  product_type         = local.am_common[each.key].product_type
  expiration_event_in  = local.am_common[each.key].expiration_event_in
  delete_protection    = local.am_common[each.key].delete_protection
  depends_on           = [terraform_data.model_guards]
  lifecycle { prevent_destroy = true }
}

resource "akeyless_auth_method_k8s" "this" {
  for_each            = local.am_by_type["k8s"]
  name                = each.key
  bound_namespaces    = try(each.value.bound_namespaces, null)
  bound_sa_names      = try(each.value.bound_sa_names, null)
  bound_pod_names     = try(each.value.bound_pod_names, null)
  audience            = try(each.value.audience, null)
  gen_key             = try(each.value.gen_key, null)
  public_key          = try(each.value.public_key, null)
  description         = local.am_common[each.key].description
  access_expires      = local.am_common[each.key].access_expires
  bound_ips           = local.am_common[each.key].bound_ips
  gw_bound_ips        = local.am_common[each.key].gw_bound_ips
  force_sub_claims    = local.am_common[each.key].force_sub_claims
  jwt_ttl             = local.am_common[each.key].jwt_ttl
  audit_logs_claims   = local.am_common[each.key].audit_logs_claims
  allowed_client_type = local.am_common[each.key].allowed_client_type
  product_type        = local.am_common[each.key].product_type
  expiration_event_in = local.am_common[each.key].expiration_event_in
  delete_protection   = local.am_common[each.key].delete_protection
  depends_on          = [terraform_data.model_guards]
  lifecycle { prevent_destroy = true }
}

resource "akeyless_auth_method_universal_identity" "this" {
  for_each            = local.am_by_type["universal_identity"]
  name                = each.key
  ttl                 = try(each.value.ttl, null)
  deny_inheritance    = try(each.value.deny_inheritance, null)
  deny_rotate         = try(each.value.deny_rotate, null)
  description         = local.am_common[each.key].description
  access_expires      = local.am_common[each.key].access_expires
  bound_ips           = local.am_common[each.key].bound_ips
  gw_bound_ips        = local.am_common[each.key].gw_bound_ips
  force_sub_claims    = local.am_common[each.key].force_sub_claims
  jwt_ttl             = local.am_common[each.key].jwt_ttl
  audit_logs_claims   = local.am_common[each.key].audit_logs_claims
  allowed_client_type = local.am_common[each.key].allowed_client_type
  product_type        = local.am_common[each.key].product_type
  expiration_event_in = local.am_common[each.key].expiration_event_in
  delete_protection   = local.am_common[each.key].delete_protection
  depends_on          = [terraform_data.model_guards]
  lifecycle { prevent_destroy = true }
}

# Name -> managed resource name (creates implicit dependencies for associations)
locals {
  managed_am_names = merge(
    { for k, r in akeyless_auth_method_api_key.this : k => r.name },
    { for k, r in akeyless_auth_method_oidc.this : k => r.name },
    { for k, r in akeyless_auth_method_saml.this : k => r.name },
    { for k, r in akeyless_auth_method_oauth2.this : k => r.name },
    { for k, r in akeyless_auth_method_aws_iam.this : k => r.name },
    { for k, r in akeyless_auth_method_azure_ad.this : k => r.name },
    { for k, r in akeyless_auth_method_k8s.this : k => r.name },
    { for k, r in akeyless_auth_method_universal_identity.this : k => r.name },
  )
}

locals {
  managed_am_access_ids = merge(
    { for k, r in akeyless_auth_method_api_key.this : k => r.access_id },
    { for k, r in akeyless_auth_method_oidc.this : k => r.access_id },
    { for k, r in akeyless_auth_method_saml.this : k => r.access_id },
    { for k, r in akeyless_auth_method_oauth2.this : k => r.access_id },
    { for k, r in akeyless_auth_method_aws_iam.this : k => r.access_id },
    { for k, r in akeyless_auth_method_azure_ad.this : k => r.access_id },
    { for k, r in akeyless_auth_method_k8s.this : k => r.access_id },
    { for k, r in akeyless_auth_method_universal_identity.this : k => r.access_id },
  )
}
