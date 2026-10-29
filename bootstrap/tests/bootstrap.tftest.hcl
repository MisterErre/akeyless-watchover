mock_provider "akeyless" {}

run "github" {
  command = plan
  variables {
    ci = { platform = "github", repository = "org/akeyless-governance" }
  }
  assert {
    condition     = akeyless_auth_method_oauth2.ci.issuer == "https://token.actions.githubusercontent.com" && akeyless_auth_method_oauth2.ci.unique_identifier == "repository"
    error_message = "github issuer/claim wrong"
  }
  assert {
    condition     = akeyless_associate_role_auth_method.apply.sub_claims["ref"] == "refs/heads/main" && akeyless_associate_role_auth_method.apply.sub_claims["repository"] == "org/akeyless-governance"
    error_message = "apply must be bound to repo + main"
  }
  assert {
    condition     = length(akeyless_associate_role_auth_method.plan.sub_claims) == 1
    error_message = "plan bound to repository only"
  }
}

run "github_enterprise_server" {
  command = plan
  variables {
    ci = { platform = "github", repository = "platform/akeyless-governance", github_url = "https://ghe.example.com/" }
  }
  assert {
    condition     = akeyless_auth_method_oauth2.ci.issuer == "https://ghe.example.com/_services/token" && akeyless_auth_method_oauth2.ci.jwks_uri == "https://ghe.example.com/_services/token/.well-known/jwks"
    error_message = "GHES issuer/jwks wrong"
  }
}

run "gitlab" {
  command = plan
  variables {
    ci = { platform = "gitlab", repository = "grp/akeyless-governance", gitlab_url = "https://gitlab.example.com/", apply_ref = "main" }
  }
  assert {
    condition     = akeyless_auth_method_oauth2.ci.jwks_uri == "https://gitlab.example.com/oauth/discovery/keys"
    error_message = "gitlab jwks wrong"
  }
  assert {
    condition     = akeyless_associate_role_auth_method.apply.sub_claims["ref_protected"] == "true" && akeyless_associate_role_auth_method.apply.sub_claims["ref"] == "main"
    error_message = "gitlab apply claims wrong"
  }
}

run "bad_platform" {
  command = plan
  variables { ci = { platform = "jenkins", repository = "x" } }
  expect_failures = [var.ci]
}
