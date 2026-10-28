# Certificates / PKI governance

* **Private CA signer**: RSA key with a CA certificate. `pki.yaml -> ca_keys` creates a DFC key with
  a self-signed certificate whose config carries `basicConstraints=critical, CA:TRUE` and
  `keyUsage=critical, keyCertSign, digitalSignature, cRLSign` (`create-dfc-key
  --generate-self-signed-certificate true --conf-file-path csr.conf`). An existing CA can be uploaded
  with `upload-rsa --cert` and referenced by name. Classic keys can sign only if Classic is enabled
  as protection-key type in account settings.
* **Issuer** = the certificate policy: allowed domains/SANs, wildcard/subdomain rules, EKU flags
  (`server_flag`, `client_flag`, `code_signing_flag`), key usage, subject fields, max TTL.
* `destination_path` stores issued certificates as items - required for `auto_renew`
  (+ `scheduled_renew_days`) and CRL. `protect_certificates` prevents their deletion.
* CRL: `create_public_crl` (served by Akeyless at `https://vault.akeyless.io/crl/<account-id>/<issuer-display-id>`)
  or `create_private_crl` (served by the Gateway; needs `gw_cluster_url`, port 8000). OCSP:
  `create_public_ocsp` / `create_private_ocsp`. ACME: `enable_acme` (needs `gw_cluster_url`).
* **Public CA** (Let's Encrypt, ZeroSSL, DigiCert, Sectigo, GlobalSign, GlobalSign Atlas, Google
  Trust...): create the CA target (`target create <ca>` / `akeyless_target_<ca>`), then an issuer with
  `ca_target` + `gw_cluster_url`. Sectigo approval workflows are not supported by the issuer.
* Expiry notifications: `expiration_event_in_days` on the issuer + an event forwarder with
  `certificate-pending-expiration` / `certificate-expired`.
* **RBAC**: issuers are items. Requesters need a rule on the issuer and on its destination path.
  The exact capability `get-pki-certificate` requires is not documented - **VERIFY** with
  `describe-permissions` (start with `read`; the reference model grants `read,list`).
