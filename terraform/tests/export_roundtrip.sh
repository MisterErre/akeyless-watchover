#!/usr/bin/env bash
# Round trip: export the fixture account (scripts/tests/fixtures/export) and prove that
#  - model mode output + imports.tf validate inside this module, and the model plans (mocked provider)
#  - hcl mode output validates as plain Terraform
# Usage: tests/export_roundtrip.sh [terraform|tofu]   (run from the terraform/ directory)
set -euo pipefail
TF="${1:-terraform}"
here="$(pwd)"
repo="$(cd .. && pwd)"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

python3 "$repo/scripts/akl_export.py" --out "$work/export" --from-dir "$repo/scripts/tests/fixtures/export" \
  --exclude '^/governance/auth/ci-terraform$' --exclude 'kerb' >/dev/null
mkdir -p "$work/mod/model/roles" "$work/mod/tests"
cp "$here"/*.tf "$work/mod/"
cp "$work/export/imports.tf" "$work/mod/"
cp "$work/export/model/roles/imported.yaml" "$work/mod/model/roles/"
cp "$work/export/model/auth_methods.imported.yaml" "$work/mod/model/auth_methods.yaml"
cp "$work/export/model/folders.imported.yaml" "$work/mod/model/folders.yaml"
cp "$work/export/model/governance.imported.yaml" "$work/mod/model/governance.yaml"
cat > "$work/mod/tests/roundtrip.tftest.hcl" <<'HCL'
mock_provider "akeyless" {}
mock_provider "akeyless" {
  alias = "gateway"
}
run "exported_model_plans" {
  command = plan
  variables {
    pipeline_access_id  = "p"
    pipeline_jwt        = "j"
    naming              = { role_prefix = "", auth_method_prefix = "" }
    auth_method_secrets = { governance_auth_sso_client_secret = "x" }
  }
  assert {
    condition     = length(akeyless_role.this) == 3 && length(akeyless_associate_role_auth_method.this) == 3
    error_message = "exported roles/associations do not plan"
  }
}
HCL
(cd "$work/mod" && "$TF" init -backend=false -input=false >/dev/null && "$TF" validate >/dev/null)
echo "ok    model mode: imports.tf + model validate in the module"
# import blocks cannot run against a mocked provider: test the model without them
rm "$work/mod/imports.tf"
(cd "$work/mod" && "$TF" test >/dev/null)
echo "ok    model mode: exported model plans (mocked provider)"

python3 "$repo/scripts/akl_export.py" --out "$work/hcl" --from-dir "$repo/scripts/tests/fixtures/export" --hcl \
  --types roles,auth-methods,folders,custom-fields,key-policies,pki-issuers,account-settings,targets,groups,gateway >/dev/null
h="$work/hcl/hcl"
"$TF" fmt -check -recursive "$h" >/dev/null
(cd "$h" && "$TF" init -backend=false -input=false >/dev/null && "$TF" validate >/dev/null)
echo "ok    hcl mode (all types incl. gateway): module tree like raw/ + imports validate, fmt-clean"
# plan the translated resources with a mocked provider (import blocks cannot run against mocks)
rm "$h/imports.tf"
cp "$h/terraform.tfvars.example" "$h/terraform.tfvars"
echo 'gateway_api = "https://gw.example.com:8000/api/v2"' >> "$h/terraform.tfvars"
mkdir -p "$h/tests"
cat > "$h/tests/plan.tftest.hcl" <<'HCL'
mock_provider "akeyless" {}
mock_provider "akeyless" {
  alias = "gateway"
}
run "translation_plans" {
  command = plan
  assert {
    condition     = akeyless_account_settings.account_settings.company_name == "Example"
    error_message = "account settings not translated"
  }
}
HCL
(cd "$h" && "$TF" test >/dev/null)
echo "ok    hcl mode: every translated resource plans (mocked provider)"

# every resource type of the provider mapping: translated attributes have valid names and types, and plan
st="$work/selftest"
python3 "$repo/scripts/tests/hcl_selftest.py" "$st" >/dev/null
(cd "$st" && "$TF" fmt -check >/dev/null && "$TF" init -backend=false -input=false >/dev/null && "$TF" test >/dev/null)
echo "ok    hcl translation self-test: every mapped resource type validates and plans (mocked provider)"
