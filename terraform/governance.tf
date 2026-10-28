############################################
# Account-wide governance objects (model/governance.yaml)
############################################

# Mandatory / optional metadata on secrets (e.g. owner, data-class)
resource "akeyless_account_custom_field" "this" {
  for_each    = local.custom_fields
  name        = try(each.value.name, each.key)
  object_type = each.value.object_type
  object      = try(each.value.object, null)
  required    = try(each.value.required, null)
  depends_on  = [terraform_data.model_guards]
}

# Key policies (allowed algorithms / protection types / max rotation per path)
resource "akeyless_policy_keys" "this" {
  for_each                   = local.key_policies
  path                       = each.key
  allowed_algorithms         = try(each.value.allowed_algorithms, null)
  allowed_key_names          = try(each.value.allowed_key_names, null)
  allowed_key_types          = try(each.value.allowed_key_types, null)
  max_rotation_interval_days = try(each.value.max_rotation_interval_days, null)
  object_types               = try(each.value.object_types, null)
  depends_on                 = [terraform_data.model_guards]
}

# Account settings: only the subset exposed by provider 2.0.5. Everything else
# (bound IPs, locks, allowed client types, max rotation interval, usage events, ...)
# is applied by scripts/akl_account_settings.py from the same YAML file.
# Destroying this resource is a no-op in Akeyless (settings stay as they are).
resource "akeyless_account_settings" "this" {
  count                                 = length(local.account_settings) > 0 ? 1 : 0
  company_name                          = try(local.account_settings.company_name, null)
  default_share_link_ttl_minutes        = try(local.account_settings.default_share_link_ttl_minutes, null)
  default_versioning                    = try(local.account_settings.default_versioning, null)
  dynamic_secret_max_ttl                = try(local.account_settings.dynamic_secret_max_ttl, null)
  dynamic_secret_max_ttl_enable         = try(local.account_settings.dynamic_secret_max_ttl_enable, null)
  enable_ai_quorum                      = try(local.account_settings.enable_ai_quorum, null)
  enable_item_sharing                   = try(local.account_settings.enable_item_sharing, null)
  enable_password_expiration            = try(local.account_settings.enable_password_expiration, null)
  hide_personal_folder                  = try(local.account_settings.hide_personal_folder, null)
  hide_static_password                  = try(local.account_settings.hide_static_password, null)
  invalid_characters                    = try(local.account_settings.invalid_characters, null)
  item_locking_enabled                  = try(local.account_settings.item_locking_enabled, null)
  items_deletion_protection             = try(local.account_settings.items_deletion_protection, null)
  jwt_ttl_default                       = try(local.account_settings.jwt_ttl_default, null)
  jwt_ttl_max                           = try(local.account_settings.jwt_ttl_max, null)
  jwt_ttl_min                           = try(local.account_settings.jwt_ttl_min, null)
  max_versions                          = try(local.account_settings.max_versions, null)
  password_expiration_days              = try(local.account_settings.password_expiration_days, null)
  password_expiration_notification_days = try(local.account_settings.password_expiration_notification_days, null)
  password_length                       = try(local.account_settings.password_length, null)
  use_capital_letters                   = try(local.account_settings.use_capital_letters, null)
  use_lower_letters                     = try(local.account_settings.use_lower_letters, null)
  use_numbers                           = try(local.account_settings.use_numbers, null)
  use_special_characters                = try(local.account_settings.use_special_characters, null)
  depends_on                            = [terraform_data.model_guards]
}

############################################
# Event forwarders (expiry, rotation, usage, access-request notifications)
############################################
locals {
  ef_by_type = { for t in local.forwarder_types : t => { for n, f in local.event_forwarders : n => f if try(f.type, "") == t } }
}

resource "akeyless_event_forwarder_email" "this" {
  for_each                            = local.ef_by_type["email"]
  name                                = each.key
  description                         = try(each.value.description, null)
  enable                              = try(tostring(each.value.enable), null)
  event_types                         = try(each.value.event_types, null)
  runner_type                         = try(each.value.runner_type, null)
  every                               = try(tostring(each.value.every), null)
  items_event_source_locations        = try(each.value.items_event_source_locations, null)
  targets_event_source_locations      = try(each.value.targets_event_source_locations, null)
  auth_methods_event_source_locations = try(each.value.auth_methods_event_source_locations, null)
  gateways_event_source_locations     = try(each.value.gateways_event_source_locations, null)
  email_to                            = try(join(",", each.value.email_to), each.value.email_to, null)
  include_error                       = try(tostring(each.value.include_error), null)
  override_url                        = try(each.value.override_url, null)
  key                                 = try(each.value.key, null)
  depends_on                          = [terraform_data.model_guards]
}

resource "akeyless_event_forwarder_webhook" "this" {
  for_each                            = local.ef_by_type["webhook"]
  name                                = each.key
  description                         = try(each.value.description, null)
  enable                              = try(tostring(each.value.enable), null)
  event_types                         = try(each.value.event_types, null)
  runner_type                         = try(each.value.runner_type, null)
  every                               = try(tostring(each.value.every), null)
  items_event_source_locations        = try(each.value.items_event_source_locations, null)
  targets_event_source_locations      = try(each.value.targets_event_source_locations, null)
  auth_methods_event_source_locations = try(each.value.auth_methods_event_source_locations, null)
  gateways_event_source_locations     = try(each.value.gateways_event_source_locations, null)
  url                                 = try(each.value.url, null)
  auth_type                           = try(each.value.auth_type, null)
  username                            = try(each.value.username, null)
  password                            = try(var.event_forwarder_secrets[each.value.password_var], null)
  auth_token                          = try(var.event_forwarder_secrets[each.value.auth_token_var], null)
  key                                 = try(each.value.key, null)
  depends_on                          = [terraform_data.model_guards]
}

resource "akeyless_event_forwarder_slack" "this" {
  for_each                            = local.ef_by_type["slack"]
  name                                = each.key
  url                                 = var.event_forwarder_secrets[each.value.url_var]
  description                         = try(each.value.description, null)
  enable                              = try(tostring(each.value.enable), null)
  event_types                         = try(each.value.event_types, null)
  runner_type                         = try(each.value.runner_type, null)
  every                               = try(tostring(each.value.every), null)
  items_event_source_locations        = try(each.value.items_event_source_locations, null)
  targets_event_source_locations      = try(each.value.targets_event_source_locations, null)
  auth_methods_event_source_locations = try(each.value.auth_methods_event_source_locations, null)
  gateways_event_source_locations     = try(each.value.gateways_event_source_locations, null)
  key                                 = try(each.value.key, null)
  depends_on                          = [terraform_data.model_guards]
}

resource "akeyless_event_forwarder_teams" "this" {
  for_each                            = local.ef_by_type["teams"]
  name                                = each.key
  url                                 = var.event_forwarder_secrets[each.value.url_var]
  runner_type                         = each.value.runner_type
  gateway_event_source_locations      = each.value.gateway_event_source_locations
  description                         = try(each.value.description, null)
  enable                              = try(tostring(each.value.enable), null)
  event_types                         = try(each.value.event_types, null)
  every                               = try(tostring(each.value.every), null)
  items_event_source_locations        = try(each.value.items_event_source_locations, null)
  targets_event_source_locations      = try(each.value.targets_event_source_locations, null)
  auth_methods_event_source_locations = try(each.value.auth_methods_event_source_locations, null)
  key                                 = try(each.value.key, null)
  depends_on                          = [terraform_data.model_guards]
}
