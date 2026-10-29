#!/usr/bin/env bash
# Proves that each negative fixture fails for the INTENDED guard (tofu/terraform test
# expect_failures only checks that the guard resource failed, not which precondition).
# Usage: tests/guard_messages.sh [tofu|terraform]   (run from the terraform/ directory)
set -euo pipefail
TF="${1:-terraform}"
tmp="tests/_guard_probe.tftest.hcl"
trap 'rm -f "$tmp"' EXIT

declare -A expect=(
  [dup]="Duplicate role name"
  [deny_mixed]="A deny rule must contain only"
  [bad_capability]="Invalid capability for the rule type"
  [bad_rule_type]="Unsupported rule type"
  [sra_conflict]="approval_authority cannot be combined"
  [root_scope]="Root-scope rule"
  [unknown_am]="Association references an auth method"
  [missing_subclaims]="force_sub_claims = true"
  [bad_prefix]="naming.role_prefix"
  [bad_mgmt]="Invalid management-plane value"
  [bad_issuer]="auto_renew requires destination_path"
  [bad_gateway]="unknown permission"
  [bad_event]="event_types must be valid"
  [bad_periodic]="runner_type periodic requires"
  [slack_no_url]="slack and teams need url_var"
)

fail=0
for fx in "${!expect[@]}"; do
  cat > "$tmp" <<HCL
mock_provider "akeyless" {}
mock_provider "akeyless" {
  alias = "gateway"
}
run "probe" {
  command = plan
  variables {
    pipeline_access_id = "p-test"
    pipeline_jwt       = "dummy"
    gateway_api        = "https://gw.example.com:8000/api/v2"
    model_dir          = "tests/fixtures/${fx}"
  }
}
HCL
  out="$("$TF" test -no-color -filter="$tmp" 2>&1 || true)"
  # error messages may be wrapped over several lines
  flat="$(printf '%s' "$out" | tr -s ' \n│' ' ')"
  if grep -qF -- "${expect[$fx]}" <<<"$flat"; then
    echo "ok    $fx -> ${expect[$fx]}"
  else
    echo "FAIL  $fx: expected '${expect[$fx]}'"; echo "$out" | tail -15; fail=1
  fi
done
exit $fail
