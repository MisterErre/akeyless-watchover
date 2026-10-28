############################################
# PKI (model/pki.yaml): private CA signer keys and certificate issuers
############################################
resource "akeyless_dfc_key" "ca" {
  for_each                         = local.ca_keys
  name                             = each.key
  alg                              = try(each.value.alg, "RSA4096")
  description                      = try(each.value.description, null)
  generate_self_signed_certificate = true
  certificate_ttl                  = each.value.certificate_ttl_days
  certificate_format               = "pem"
  conf_file_data = base64encode(join("\n", concat(
    [for k, v in try(each.value.subject, {}) : "${k}=${v}"],
    ["", "[ v3_req ]",
      "basicConstraints=critical, CA:TRUE${try(each.value.path_len, null) != null ? ", pathlen:${each.value.path_len}" : ""}",
    "keyUsage=critical, keyCertSign, digitalSignature, cRLSign", ""]
  )))
  delete_protection = try(each.value.delete_protection, true) # bool on this resource
  tags              = try(each.value.tags, null)
  depends_on        = [terraform_data.model_guards]
  lifecycle { prevent_destroy = true }
}

resource "akeyless_pki_cert_issuer" "this" {
  for_each = local.issuers
  name     = each.key
  ttl      = tostring(each.value.ttl_seconds) # provider documents seconds
  # Private CA: signer managed here (resolved for dependency ordering) or existing key name
  signer_key_name = try(akeyless_dfc_key.ca[each.value.signer_key_name].name, each.value.signer_key_name, null)
  # Public CA: target name + Gateway
  ca_target      = try(each.value.ca_target, null)
  gw_cluster_url = try(each.value.gw_cluster_url, null)

  description              = try(each.value.description, null)
  allowed_domains          = try(join(",", each.value.allowed_domains), each.value.allowed_domains, null)
  allowed_uri_sans         = try(join(",", each.value.allowed_uri_sans), each.value.allowed_uri_sans, null)
  allowed_ip_sans          = try(join(",", each.value.allowed_ip_sans), each.value.allowed_ip_sans, null)
  allow_subdomains         = try(each.value.allow_subdomains, null)
  allow_any_name           = try(each.value.allow_any_name, null)
  disable_wildcards        = try(each.value.disable_wildcards, null)
  not_enforce_hostnames    = try(each.value.not_enforce_hostnames, null)
  not_require_cn           = try(each.value.not_require_cn, null)
  server_flag              = try(each.value.server_flag, null)
  client_flag              = try(each.value.client_flag, null)
  code_signing_flag        = try(each.value.code_signing_flag, null)
  key_usage                = try(join(",", each.value.key_usage), each.value.key_usage, null)
  critical_key_usage       = try(tostring(each.value.critical_key_usage), null)
  organizations            = try(each.value.organizations, null)
  organizational_units     = try(each.value.organizational_units, null)
  country                  = try(each.value.country, null)
  locality                 = try(each.value.locality, null)
  province                 = try(each.value.province, null)
  max_path_len             = try(each.value.max_path_len, null)
  destination_path         = try(each.value.destination_path, null)
  protect_certificates     = try(each.value.protect_certificates, null)
  auto_renew               = try(each.value.auto_renew, null)
  scheduled_renew          = try(each.value.scheduled_renew_days, null)
  expiration_event_in      = try([for d in each.value.expiration_event_in_days : tostring(d)], null)
  create_public_crl        = try(each.value.create_public_crl, null)
  create_private_crl       = try(each.value.create_private_crl, null)
  create_public_ocsp       = try(each.value.create_public_ocsp, null)
  create_private_ocsp      = try(each.value.create_private_ocsp, null)
  enable_acme              = try(each.value.enable_acme, null)
  allowed_extra_extensions = try(jsonencode(each.value.allowed_extra_extensions), null)
  delete_protection        = try(each.value.delete_protection, true) # bool on this resource
  tags                     = try(each.value.tags, null)
  depends_on               = [terraform_data.model_guards]
}
