resource "akeyless_role" "this" {
  for_each    = local.roles
  name        = each.key
  description = try(each.value.description, null)

  # Management-plane visibility (none | own | scoped | all, per attribute)
  audit_access            = try(each.value.audit_access, null)
  analytics_access        = try(each.value.analytics_access, null)
  gw_analytics_access     = try(each.value.gw_analytics_access, null)
  sra_reports_access      = try(each.value.sra_reports_access, null)
  usage_reports_access    = try(each.value.usage_reports_access, null)
  event_center_access     = try(each.value.event_center_access, null)
  event_forwarders_access = try(each.value.event_forwarders_access, null)
  event_forwarders_name   = try(each.value.event_forwarders_name, null)
  reverse_rbac_access     = try(each.value.reverse_rbac_access, null)
  isi_access              = try(each.value.isi_access, null)
  unlock_secrets          = try(each.value.unlock_secrets, null)
  approve_access_request  = try(each.value.approve_access_request, null)
  delete_protection       = try(tostring(each.value.delete_protection), null)

  # AUTHORITATIVE: rules present in Akeyless but absent here are removed on apply.
  dynamic "rules" {
    for_each = try(each.value.rules, [])
    content {
      path       = rules.value.path
      capability = rules.value.capabilities
      rule_type  = try(rules.value.type, "item-rule")
    }
  }
  # Never use the deprecated assoc_auth_method block here; see associations below.

  depends_on = [terraform_data.model_guards]
}

resource "akeyless_associate_role_auth_method" "this" {
  for_each       = local.associations
  role_name      = akeyless_role.this[each.value.role].name
  am_name        = try(local.managed_am_names[each.value.auth_method], each.value.auth_method)
  sub_claims     = length(each.value.sub_claims) > 0 ? each.value.sub_claims : null
  case_sensitive = each.value.case_sensitive
}
