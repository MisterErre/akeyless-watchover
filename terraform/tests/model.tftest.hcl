# Offline tests: the provider is mocked, no Akeyless account is touched.
mock_provider "akeyless" {}
mock_provider "akeyless" {
  alias = "gateway"
}

variables {
  pipeline_access_id      = "p-test"
  pipeline_jwt            = "dummy"
  gateway_api             = "https://gw.example.com:8000/api/v2"
  auth_method_secrets     = { entra_oidc_client_secret = "dummy" }
  event_forwarder_secrets = {}
  gateway_secrets         = { conjur_api_key = "dummy" }
}

run "reference_model_plans" {
  command = plan

  assert {
    condition     = length(akeyless_role.this) == 4
    error_message = "expected 4 roles"
  }
  assert {
    condition     = length(akeyless_associate_role_auth_method.this) == 5
    error_message = "expected 5 associations"
  }
  assert {
    condition     = length(akeyless_role.this["/governance/roles/payments/checkout-prod-workload"].rules) == 2
    error_message = "checkout-prod-workload should have 2 rules"
  }
  assert {
    condition     = akeyless_associate_role_auth_method.this["/governance/roles/payments/team-admin|/governance/auth/sso-entra-oidc"].sub_claims["groups"] == "grp-akl-payments-admins"
    error_message = "list sub-claims must be joined"
  }
  assert {
    condition     = akeyless_associate_role_auth_method.this["/governance/roles/payments/team-admin|/governance/auth/sso-entra-oidc"].am_name == "/governance/auth/sso-entra-oidc"
    error_message = "am_name must resolve to managed auth method"
  }
  assert {
    condition     = length(akeyless_auth_method_oidc.this) == 1 && length(akeyless_auth_method_k8s.this) == 1 && length(akeyless_auth_method_aws_iam.this) == 1
    error_message = "auth methods not split by type"
  }
  assert {
    condition     = length(akeyless_folder.this) == 3
    error_message = "expected 3 folders"
  }
  assert {
    condition     = length(akeyless_account_custom_field.this) == 2 && length(akeyless_policy_keys.this) == 1 && length(akeyless_account_settings.this) == 1
    error_message = "governance objects missing"
  }
  assert {
    condition     = length(akeyless_event_forwarder_email.this) == 1 && akeyless_event_forwarder_email.this["/governance/events/secops-email"].email_to == "secops@example.com"
    error_message = "email forwarder not rendered"
  }
  assert {
    condition     = akeyless_pki_cert_issuer.this["/pki/issuers/payments-server"].ttl == "7776000" && akeyless_pki_cert_issuer.this["/pki/issuers/payments-server"].key_usage == "DigitalSignature,KeyEncipherment"
    error_message = "issuer attributes not rendered"
  }
  assert {
    condition     = strcontains(base64decode(akeyless_dfc_key.ca["/pki/ca/internal-root"].conf_file_data), "basicConstraints=critical, CA:TRUE")
    error_message = "CA conf must carry CA:TRUE"
  }
  assert {
    condition     = length(akeyless_gateway_allowed_access.this) == 2 && akeyless_gateway_allowed_access.this["platform-admins"].permissions == "admin"
    error_message = "gateway allowed access not rendered"
  }
  assert {
    condition     = akeyless_gateway_migration_conjur.this["conjur-prod"].target_location == "/conjur"
    error_message = "conjur migration not rendered"
  }
  assert {
    condition     = length(akeyless_gateway_log_forwarding_syslog.this) == 1 && length(akeyless_gateway_log_forwarding_splunk.this) == 0
    error_message = "log forwarding selection wrong"
  }
}

run "gateway_objects_need_gateway_api" {
  command = plan
  variables { gateway_api = null }
  expect_failures = [terraform_data.model_guards]
}

run "ara_rule_allowed_when_enabled" {
  command = plan
  variables {
    model_dir       = "tests/fixtures/ara_allowed"
    allow_ara_rules = true
  }
  assert {
    condition     = length(akeyless_role.this) == 1
    error_message = "ara fixture should plan"
  }
}

run "root_scope_allowed_with_flag" {
  command = plan
  variables { model_dir = "tests/fixtures/root_allowed" }
  assert {
    condition     = length(akeyless_role.this) == 1
    error_message = "root_allowed fixture should plan"
  }
}

run "dup" {
  command = plan
  variables { model_dir = "tests/fixtures/dup" }
  expect_failures = [terraform_data.model_guards]
}
run "deny_mixed" {
  command = plan
  variables { model_dir = "tests/fixtures/deny_mixed" }
  expect_failures = [terraform_data.model_guards]
}
run "bad_capability" {
  command = plan
  variables { model_dir = "tests/fixtures/bad_capability" }
  expect_failures = [terraform_data.model_guards]
}
run "bad_rule_type" {
  command = plan
  variables { model_dir = "tests/fixtures/bad_rule_type" }
  expect_failures = [terraform_data.model_guards]
}
run "sra_conflict" {
  command = plan
  variables { model_dir = "tests/fixtures/sra_conflict" }
  expect_failures = [terraform_data.model_guards]
}
run "root_scope" {
  command = plan
  variables { model_dir = "tests/fixtures/root_scope" }
  expect_failures = [terraform_data.model_guards]
}
run "unknown_am" {
  command = plan
  variables { model_dir = "tests/fixtures/unknown_am" }
  expect_failures = [terraform_data.model_guards]
}
run "missing_subclaims" {
  command = plan
  variables { model_dir = "tests/fixtures/missing_subclaims" }
  expect_failures = [terraform_data.model_guards]
}
run "bad_prefix" {
  command = plan
  variables { model_dir = "tests/fixtures/bad_prefix" }
  expect_failures = [terraform_data.model_guards]
}
run "bad_mgmt" {
  command = plan
  variables { model_dir = "tests/fixtures/bad_mgmt" }
  expect_failures = [terraform_data.model_guards]
}
run "bad_issuer" {
  command = plan
  variables { model_dir = "tests/fixtures/bad_issuer" }
  expect_failures = [terraform_data.model_guards]
}
run "bad_gateway" {
  command = plan
  variables { model_dir = "tests/fixtures/bad_gateway" }
  expect_failures = [terraform_data.model_guards]
}
run "bad_event" {
  command = plan
  variables { model_dir = "tests/fixtures/bad_event" }
  expect_failures = [terraform_data.model_guards]
}

run "scaffolded_forwarders_plan" {
  # fixture written by `watchover forwarder` (tests/fixtures/forwarders/generate.sh)
  command = plan
  variables {
    model_dir = "tests/fixtures/forwarders"
    event_forwarder_secrets = {
      governance_events_siem_token           = "dummy"
      governance_events_pki_slack_url        = "https://hooks.slack.com/services/dummy"
      governance_events_ops_teams_url        = "https://example.webhook.office.com/dummy"
      governance_events_snow_client_secret   = "dummy"
      governance_events_snow_app_private_key = "ZHVtbXk="
    }
  }
  assert {
    condition = (length(akeyless_event_forwarder_email.this) + length(akeyless_event_forwarder_webhook.this) +
      length(akeyless_event_forwarder_slack.this) + length(akeyless_event_forwarder_teams.this) +
    length(akeyless_event_forwarder_service_now.this)) == 5
    error_message = "expected one forwarder of each of the 5 types"
  }
  assert {
    condition     = akeyless_event_forwarder_email.this["/governance/events/secops-mail"].email_to == "secops@example.com,pam@example.com"
    error_message = "email_to list must be joined with commas"
  }
  assert {
    condition     = akeyless_event_forwarder_slack.this["/governance/events/pki-slack"].every == "24"
    error_message = "periodic digest interval not passed"
  }
  assert {
    condition     = akeyless_event_forwarder_service_now.this["/governance/events/snow"].enable == "false"
    error_message = "--disabled must set enable = false"
  }
}
run "bad_periodic" {
  command = plan
  variables { model_dir = "tests/fixtures/bad_periodic" }
  expect_failures = [terraform_data.model_guards]
}
run "slack_no_url" {
  command = plan
  variables { model_dir = "tests/fixtures/slack_no_url" }
  expect_failures = [terraform_data.model_guards]
}

run "empty_gateway_api_is_unset" {
  command = plan
  variables { gateway_api = "" }
  expect_failures = [terraform_data.model_guards]
}

run "naming_check_disabled_with_empty_string" {
  command = plan
  variables {
    model_dir = "tests/fixtures/bad_prefix"
    naming    = { role_prefix = "", auth_method_prefix = "" }
  }
  assert {
    condition     = length(akeyless_role.this) == 1
    error_message = "bad_prefix fixture should plan when naming checks are disabled"
  }
}
