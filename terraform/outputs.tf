output "auth_method_access_ids" {
  description = "Access IDs to hand to consumers (non-secret)."
  value       = local.managed_am_access_ids
}

output "role_names" {
  description = "Managed access roles."
  value       = sort(keys(akeyless_role.this))
}

output "association_count" {
  value = length(akeyless_associate_role_auth_method.this)
}
