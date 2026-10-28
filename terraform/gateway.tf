############################################
# Gateway admin plane (model/gateway.yaml) - applied through local.gateway_api.
# One Gateway cluster per state: use a workspace / var-file per cluster.
############################################
resource "akeyless_gateway_allowed_access" "this" {
  provider    = akeyless.gateway
  for_each    = local.gateway_api == null ? {} : local.gw_allowed_access
  name        = each.key
  access_id   = try(local.managed_am_access_ids[each.value.auth_method], each.value.access_id)
  permissions = join(",", each.value.permissions)
  sub_claims = try(length(each.value.sub_claims) > 0, false) ? {
    for k, v in each.value.sub_claims : k => try(join(",", v), tostring(v))
  } : null
  case_sensitive = try(tostring(each.value.case_sensitive), null)
  description    = try(each.value.description, null)
  depends_on     = [terraform_data.model_guards]
}

# Audit-log forwarding to a SIEM (singleton per Gateway)
resource "akeyless_gateway_log_forwarding_syslog" "this" {
  provider      = akeyless.gateway
  count         = local.gateway_api != null && try(local.gw_log_forwarding.type, "") == "syslog" ? 1 : 0
  enable        = "true"
  host          = local.gw_log_forwarding.host
  network       = try(local.gw_log_forwarding.network, null)
  enable_tls    = try(local.gw_log_forwarding.enable_tls, null)
  formatter     = try(local.gw_log_forwarding.formatter, null)
  output_format = try(local.gw_log_forwarding.output_format, null)
  target_tag    = try(local.gw_log_forwarding.target_tag, null)
  pull_interval = try(tostring(local.gw_log_forwarding.pull_interval), null)
  depends_on    = [terraform_data.model_guards]
}

resource "akeyless_gateway_log_forwarding_splunk" "this" {
  provider      = akeyless.gateway
  count         = local.gateway_api != null && try(local.gw_log_forwarding.type, "") == "splunk" ? 1 : 0
  enable        = "true"
  splunk_url    = local.gw_log_forwarding.splunk_url
  splunk_token  = var.gateway_secrets[local.gw_log_forwarding.splunk_token_var]
  index         = try(local.gw_log_forwarding.index, null)
  source        = try(local.gw_log_forwarding.source, null)
  source_type   = try(local.gw_log_forwarding.source_type, null)
  enable_tls    = try(local.gw_log_forwarding.enable_tls, null)
  enable_batch  = try(tostring(local.gw_log_forwarding.enable_batch), null)
  output_format = try(local.gw_log_forwarding.output_format, null)
  pull_interval = try(tostring(local.gw_log_forwarding.pull_interval), null)
  depends_on    = [terraform_data.model_guards]
}

# Secret migration from CyberArk Conjur (values only - RBAC is translated by
# scripts/conjur2akeyless.py). The Conjur API key comes from var.gateway_secrets.
resource "akeyless_gateway_migration_conjur" "this" {
  provider        = akeyless.gateway
  for_each        = local.gateway_api == null ? {} : try(local.gateway.migrations.conjur, {})
  name            = each.key
  target_location = each.value.target_location
  conjur_url      = each.value.conjur_url
  conjur_account  = each.value.conjur_account
  conjur_username = each.value.conjur_username
  conjur_api_key  = var.gateway_secrets[each.value.conjur_api_key_var]
  protection_key  = try(each.value.protection_key, null)
  depends_on      = [terraform_data.model_guards]
}
