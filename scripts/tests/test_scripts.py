import json
import os
import subprocess
import sys

import pytest
import yaml

HERE = os.path.dirname(__file__)
SCRIPTS = os.path.dirname(HERE)
REPO = os.path.dirname(SCRIPTS)
sys.path.insert(0, SCRIPTS)

import akl_model as m  # noqa: E402
from akl_account_settings import build_args  # noqa: E402


def run(*args, cwd=REPO):
    return subprocess.run([sys.executable, *args], capture_output=True, text=True, cwd=cwd)


# ---------- path semantics ----------
@pytest.mark.parametrize("pattern,path,ok", [
    ("/a/*", "/a/b", True),
    ("/a/*", "/a/b/c", True),
    ("/a/*", "/a", False),
    ("/a/devops-*", "/a/devops-x/y", True),
    ("/a/devops-*", "/a/dev", False),
    ("/a/+/c/*", "/a/x/c/d", True),
    ("/a/+/c/*", "/a/x/y/c/d", False),
    ("a/b", "/a/b", True),
    ("/a/b", "/a/bc", False),
    ("/a.b/*", "/aXb/c", False),
])
def test_path_matches(pattern, path, ok):
    assert m.path_matches(pattern, path) is ok


# ---------- sub-claims ----------
def test_sub_claims_or_within_key_and_across_keys():
    req = {"groups": "a,b", "env": ["prod"]}
    assert m.sub_claims_match(req, {"groups": ["b"], "env": ["prod"]})
    assert not m.sub_claims_match(req, {"groups": ["b"]})
    assert not m.sub_claims_match(req, {"groups": ["c"], "env": ["prod"]})


def test_sub_claims_glob_and_case():
    assert m.sub_claims_match({"email": "*@example.com"}, {"email": ["x@example.com"]})
    assert m.sub_claims_match({"id": "1?1"}, {"id": "121"})
    assert not m.sub_claims_match({"id": "1?1"}, {"id": "1231"})
    assert not m.sub_claims_match({"groups": "Admins"}, {"groups": ["admins"]})
    assert m.sub_claims_match({"groups": "Admins"}, {"groups": ["admins"]}, case_sensitive=False)


def test_sub_claims_operators():
    assert m.sub_claims_match({"groups": "a AND b"}, {"groups": ["a", "b"]})
    assert not m.sub_claims_match({"groups": "a AND b"}, {"groups": ["a"]})
    assert m.sub_claims_match({"groups": "a OR z"}, {"groups": ["z"]})


def test_templates_and_deny():
    model = m.Model(roles={
        "/r/personal": {"rules": [{"path": "/personal/{{email}}/*", "capabilities": ["read", "update"]},
                                  {"path": "/personal/+/locked/*", "capabilities": ["deny"]}],
                        "associations": [{"auth_method": "/am/sso"}]},
    })
    caps, _ = m.effective_capabilities(model, "/am/sso", {"email": ["a@x"]}, "/personal/a@x/k")
    assert caps == {"read", "update", "list"}
    caps, _ = m.effective_capabilities(model, "/am/sso", {"email": ["a@x"]}, "/personal/b@x/k")
    assert caps == set()
    caps, why = m.effective_capabilities(model, "/am/sso", {"email": ["a@x"]}, "/personal/a@x/locked/k")
    assert caps == set() and "deny" in why[-1]


def test_rule_type_isolation():
    model = m.Model(roles={"/r": {"rules": [{"path": "/*", "capabilities": ["read"], "type": "role-rule"}],
                                  "associations": [{"auth_method": "/am"}]}})
    assert m.effective_capabilities(model, "/am", {}, "/x", "item")[0] == set()
    assert m.effective_capabilities(model, "/am", {}, "/x", "role")[0] == {"read", "list"}


# ---------- reference model + simulator ----------
def test_reference_model_expectations_pass():
    r = run("scripts/akl_simulate.py", "--model", "terraform/model",
            "--expectations", "terraform/model/access_expectations.yaml")
    assert r.returncode == 0, r.stdout + r.stderr


def test_simulator_detects_mismatch(tmp_path):
    exp = yaml.safe_load(open(os.path.join(REPO, "terraform/model/access_expectations.yaml")))
    exp["checks"] = [{"persona": "random-employee", "path": "/payments/checkout/prod/db/app", "expect": ["read"]}]
    f = tmp_path / "e.yaml"
    f.write_text(yaml.safe_dump(exp))
    r = run("scripts/akl_simulate.py", "--model", "terraform/model", "--expectations", str(f))
    assert r.returncode == 1 and "FAIL" in r.stdout


# ---------- account settings ----------
def test_account_settings_args():
    args = build_args({"bound-ips": ["10.0.0.0/8", "172.16.0.0/12"], "lock-bound-ips": True, "usage-event-interval": 90})
    assert args == ["--bound-ips=10.0.0.0/8", "--bound-ips=172.16.0.0/12", "--lock-bound-ips=true", "--usage-event-interval=90"]


@pytest.mark.parametrize("bad", [{"jwt-ttl-default": 60}, {"no-such-flag": 1}])
def test_account_settings_rejects(bad):
    with pytest.raises(ValueError):
        build_args(bad)


def test_account_settings_reference_dry_run():
    r = run("scripts/akl_account_settings.py", "--governance", "terraform/model/governance.yaml", "--dry-run")
    assert r.returncode == 0 and "update-account-settings" in r.stdout


# ---------- exporter ----------
FX = os.path.join(HERE, "fixtures/export")


def export(tmp_path, *args):
    return run("scripts/akl_export.py", "--out", str(tmp_path), "--from-dir", FX, *args)


def test_export_model_mode(tmp_path):
    r = export(tmp_path, "--exclude", "^/governance/auth/ci-terraform$")
    assert r.returncode == 0, r.stderr
    roles = yaml.safe_load(open(tmp_path / "model/roles/imported.yaml"))["roles"]
    team = roles["/governance/roles/payments/team-admin"]
    assert team["audit_access"] == "scoped" and team["analytics_access"] == "all"
    assert {"path": "/srv/*", "capabilities": ["allow_access"], "type": "sra-rule"} in team["rules"]
    assert not any(ru["path"] in ("/payments/tmp", "/x") for ru in team["rules"])  # ttl + unknown type skipped
    assert team["associations"][0] == {"auth_method": "/governance/auth/sso", "sub_claims": {"groups": ["grp-a", "grp-b"]},
                                       "case_sensitive": False}
    assert team["allow_external_auth_methods"] is True  # ci-terraform excluded
    assert roles["/governance/roles/platform/god"]["allow_root_scope"] is True
    ams = yaml.safe_load(open(tmp_path / "model/auth_methods.imported.yaml"))["auth_methods"]
    sso = ams["/governance/auth/sso"]
    assert sso["type"] == "oidc" and sso["issuer"].startswith("https://login") and sso["client_id"] == "cid"
    assert sso["allowed_redirect_uri"] == ["https://console.akeyless.io"] and sso["unique_identifier"] == "email"
    assert sso["bound_ips"] == ["10.0.0.0/8", "192.168.0.0/16"] and sso["client_secret_var"] == "governance_auth_sso_client_secret"
    assert "client_secret" not in sso
    assert ams["/governance/auth/aws-payments-prod"] == {"type": "aws_iam", "bound_aws_account_id": ["123456789012"],
                                                         "bound_role_name": ["payments-app"], "sts_url": "https://sts.amazonaws.com"}
    az = ams["/governance/auth/azure-prod"]
    assert az["bound_spid"] == ["sp1"] and az["audience"] == "https://management.azure.com/"
    assert ams["/governance/auth/k8s-prod"]["bound_sa_names"] == ["api"]
    assert ams["/legacy/kerb"]["type"].startswith("TODO")
    folders = yaml.safe_load(open(tmp_path / "model/folders.imported.yaml"))["folders"]
    assert folders == {"/payments": {"description": "Payments BU", "tags": ["bu:payments"], "delete_protection": True}}
    gov = yaml.safe_load(open(tmp_path / "model/governance.imported.yaml"))
    assert gov["custom_fields"]["owner-static-secret"]["required"] is True
    assert gov["key_policies"]["/payments/*"]["allowed_algorithms"] == ["AES256GCM"]
    imports = open(tmp_path / "imports.tf").read()
    for needle in ('to = akeyless_auth_method_oidc.this["/governance/auth/sso"]',
                   'id = "/governance/roles/payments/team-admin:/governance/auth/sso"',
                   'to = akeyless_folder.this["/payments"]',
                   'to = akeyless_account_custom_field.this["owner-static-secret"]\n  id = "101"',
                   'to = akeyless_policy_keys.this["/payments/*"]\n  id = "pol-1"'):
        assert needle in imports, needle
    assert "kerb" not in imports
    report = open(tmp_path / "REPORT.md").read()
    for needle in ("brand-new-rule", "temporary rule", "client secret not exported", "PKI issuer", "5 discovered"):
        assert needle in report, needle


def test_export_never_writes_secrets(tmp_path):
    export(tmp_path)
    for root, _dirs, files in os.walk(tmp_path):
        for f in files:
            text = open(os.path.join(root, f)).read()
            assert "s3cr3t" not in text and "PUBLICKEYDATA" not in text, f
    raw = json.load(open(tmp_path / "raw/auth_methods/governance_auth_sso.json"))
    assert raw["access_info"]["oidc_access_rules"]["client_secret"] == "<redacted>"


@pytest.mark.parametrize("claim,expected", [
    ("groups=grp-a", ["/governance/roles/payments/team-admin"]),
    ("groups=GRP-B", ["/governance/roles/payments/team-admin"]),      # association is case-insensitive
    ("groups=grp-auditors", ["/governance/roles/platform/auditors"]),
    ("groups=nobody", []),
])
def test_export_persona_view(tmp_path, claim, expected):
    r = export(tmp_path, "--persona-auth-method", "/governance/auth/sso", "--persona-claim", claim)
    assert r.returncode == 0, r.stderr
    roles = yaml.safe_load(open(tmp_path / "model/roles/imported.yaml"))["roles"]
    assert sorted(roles) == expected
    ams = yaml.safe_load(open(tmp_path / "model/auth_methods.imported.yaml"))["auth_methods"]
    assert list(ams) == ["/governance/auth/sso"]


def test_export_types_and_only(tmp_path):
    r = export(tmp_path, "--types", "auth-methods", "--only", "aws|azure")
    assert r.returncode == 0, r.stderr
    ams = yaml.safe_load(open(tmp_path / "model/auth_methods.imported.yaml"))["auth_methods"]
    assert sorted(ams) == ["/governance/auth/aws-payments-prod", "/governance/auth/azure-prod"]
    assert yaml.safe_load(open(tmp_path / "model/roles/imported.yaml"))["roles"] == {}


def _hcl_files(d):
    return sorted(os.path.relpath(os.path.join(r, f), d) for r, _ds, fs in os.walk(d) for f in fs)


def test_export_hcl_mode(tmp_path):
    r = export(tmp_path, "--hcl")
    assert r.returncode == 0, r.stderr
    hcl_dir, raw = tmp_path / "hcl", tmp_path / "raw"
    files = _hcl_files(hcl_dir)
    # same layout as raw/: every translated JSON file has a .tf twin at the same relative path
    for sub in ("roles", "auth_methods", "folders"):
        for f in os.listdir(raw / sub):
            assert os.path.join(sub, f[:-5] + ".tf") in files, (sub, f)
    assert "items/pki_issuers_payments-server.tf" in files and "items/payments_checkout_prod_db.tf" not in files
    for root_file in ("custom_fields.tf", "policies.tf", "account_settings.tf", "versions.tf", "main.tf", "imports.tf",
                      "terraform.tfvars.example"):
        assert root_file in files, root_file
    # complete resources, not just import blocks
    role = (hcl_dir / "roles/governance_roles_payments_team-admin.tf").read_text()
    for needle in ('resource "akeyless_role"', 'audit_access      = "scoped"', 'capability = ["create", "list", "read"]',
                   'rule_type  = "sra-rule"', 'sub_claims     = { "groups" = "grp-a,grp-b" }', 'case_sensitive = "false"',
                   "temporary rule skipped"):
        assert needle in role, needle
    oidc = (hcl_dir / "auth_methods/governance_auth_sso.tf").read_text()
    for needle in ('issuer               = "https://login.microsoftonline.com/t/v2.0"', 'bound_ips            = ["10.0.0.0/8", "192.168.0.0/16"]',
                   'client_secret        = var.secrets["/governance/auth/sso:client_secret"]', "jwt_ttl              = 60"):
        assert needle in oidc, needle
    assert 'description       = "Payments BU"' in (hcl_dir / "folders/payments.tf").read_text()
    assert "max_rotation_interval_days = 365" in (hcl_dir / "policies.tf").read_text()
    assert '# raw access_info.kerberos_access_rules.realm = "EX.COM"' in (hcl_dir / "auth_methods/legacy_kerb.tf").read_text()
    # secrets never written, even in comments
    alltext = "".join((hcl_dir / f).read_text() for f in files)
    for secret in ("s3cr3t", "PUBLICKEYDATA"):
        assert secret not in alltext and secret not in "".join((raw / f).read_text() for f in _hcl_files(raw))
    assert '"/governance/auth/sso:client_secret" = ""' in (hcl_dir / "terraform.tfvars.example").read_text()
    imports = (hcl_dir / "imports.tf").read_text()
    for needle in ("to = module.auth_methods.akeyless_auth_method_kerberos.legacy_kerb",
                   "to = module.items.akeyless_pki_cert_issuer.pki_issuers_payments_server",
                   "to = akeyless_account_settings.account_settings", "to = akeyless_policy_keys.payments\n",
                   'id = "/governance/roles/payments/team-admin:/governance/auth/ci-terraform"'):
        assert needle in imports, needle
    assert 'module "roles"' in (hcl_dir / "main.tf").read_text()
    assert "api_gateway_address" in (hcl_dir / "versions.tf").read_text()
    assert not (tmp_path / "imports.tf").exists()


def test_hcl_translation_rules():
    import akl_hcl as H
    assert H.coerce("a, b", ["list", "string"]) == ["a", "b"] and H.coerce(True, "string") == "true"
    assert H.coerce("60", "number") == 60 and H.coerce("false", "bool") is False
    assert H.transform(["x", "y"], "join_comma") == "x,y" and H.transform(True, "not_tostring") == "false"
    assert H.get_path({"policy": {"path": "/a"}}, ["policy", "path"]) == "/a"
    assert H.get_path({"path": "/a"}, ["policy", "path"]) == "/a"           # list endpoints: inner object
    assert H.get_path({"body": {"m": [{"g": {"n": 1}}]}}, ["body", "m", "g", "n"]) == 1
    assert H.lit("${x}") == '"$${x}"' and H.lit({"a": ["b"]}) == '{ "a" = ["b"] }'
    assert H.is_secret("client_secret", ["string", "O", False]) and not H.is_secret("key", ["string", "O", False])
    assert H.placeholder("inputs", "k", "number") == 'tonumber(var.inputs["k"])'


def test_provider_mapping_data_covers_every_emitted_resource():
    import akl_export as E
    import akl_hcl as H
    emitted = ["akeyless_role", "akeyless_associate_role_auth_method", "akeyless_folder", "akeyless_account_custom_field",
               "akeyless_policy_keys", "akeyless_pki_cert_issuer", "akeyless_account_settings", "akeyless_group",
               "akeyless_gateway_defaults", "akeyless_gateway_cache", "akeyless_gateway_remote_access",
               "akeyless_gateway_allowed_access"]
    emitted += [f"akeyless_auth_method_{t}" for t, _m in E.AM_RULES.values()] + \
               [f"akeyless_auth_method_{t}" for t in E.OTHER_AM_RESOURCE.values()]
    emitted += [f"akeyless_target_{t}" for t in E.TARGET_RESOURCES]
    emitted += [f"akeyless_gateway_migration_{t}" for t in E.GW_MIGRATIONS.values()]
    emitted += [f"akeyless_gateway_log_forwarding_{t}" for t in E.GW_LOG_CONFIGS.values()]
    missing = [r for r in emitted if r not in H.DATA]
    assert not missing, missing
    # read mappings exist for the families the provider reads directly
    for r in ("akeyless_auth_method_oidc", "akeyless_pki_cert_issuer", "akeyless_target_aws", "akeyless_gateway_defaults",
              "akeyless_gateway_migration_conjur", "akeyless_account_settings"):
        assert H.DATA[r]["map"], r


@pytest.mark.parametrize("args", [["--types", "secrets"], ["--generate"], ["--persona-claim", "a=b"],
                                  ["--persona-auth-method", "/x", "--persona-claim", "novalue"]])
def test_export_usage_errors(tmp_path, args):
    assert export(tmp_path, *args).returncode == 2


# ---------- transports: cli / api / from-dir must agree ----------
import fake_backend  # noqa: E402


def _tree(d):
    out = {}
    for root, _dirs, files in os.walk(d):
        for f in files:
            rel = os.path.relpath(os.path.join(root, f), d)
            if not rel.startswith("raw"):
                out[rel] = open(os.path.join(root, f)).read()
    return out


def _fake_cli(tmp_path):
    exe = tmp_path / "akeyless"
    exe.write_text(f"#!/bin/sh\nexec {sys.executable} {os.path.join(HERE, 'fake_backend.py')} \"$@\"\n")
    exe.chmod(0o755)
    return str(exe)


@pytest.mark.parametrize("mode", [[], ["--hcl", "--types", ",".join(__import__("akl_export").TYPES)]])
def test_transports_produce_identical_output(tmp_path, mode):
    log = []
    srv = fake_backend.serve(log)
    api = f"http://127.0.0.1:{srv.server_address[1]}"
    try:
        r1 = run("scripts/akl_export.py", "--out", str(tmp_path / "dir"), "--from-dir", FX, *mode)
        r2 = subprocess.run([sys.executable, os.path.join(SCRIPTS, "akl_export.py"), "--out", str(tmp_path / "cli"),
                             "--transport", "cli", "--akeyless", _fake_cli(tmp_path), "--profile", "p",
                             "--gateway-url", "https://gw:8000", *mode],
                            capture_output=True, text=True, env={**os.environ, "FAKE_AKL_LOG": str(tmp_path / "cli.log")})
        r3 = run("scripts/akl_export.py", "--out", str(tmp_path / "api"), "--transport", "api", "--api", api,
                 "--token", "T0KEN", "--gateway-api", api + "/gw/api/v2", *mode)
    finally:
        srv.shutdown()
    for r in (r1, r2, r3):
        assert r.returncode == 0, r.stderr
    a, b, c = _tree(tmp_path / "dir"), _tree(tmp_path / "cli"), _tree(tmp_path / "api")
    assert a.keys() == b.keys() == c.keys()
    for k in a:
        if k != "REPORT.md":  # item counts differ: the dir replay lists every saved item
            assert a[k] == b[k] == c[k], k
    # REST: token in every body, Gateway calls to the Gateway API
    assert log and all(body.get("token") == "T0KEN" for _p, body in log)
    assert ("/get-role", {"name": "/governance/roles/payments/team-admin", "token": "T0KEN"}) in log
    if mode:
        assert any(p == "/gw/api/v2/gateway-get-config" for p, _b in log)
    # CLI: exact command words and flags
    calls = [json.loads(line) for line in open(tmp_path / "cli.log")]
    assert ["folder", "get", "--name", "/payments", "--json", "--profile", "p"] in calls
    assert ["list-roles", "--pagination-token", "p1", "--json", "--profile", "p"] in calls
    # every list stops at the first empty page although the back end always returns a next_page token
    roles = len(os.listdir(os.path.join(FX_EXPORT, "roles")))
    assert ["list-roles", "--pagination-token", f"p{roles}", "--json", "--profile", "p"] in calls
    assert ["list-roles", "--pagination-token", f"p{roles + 1}", "--json", "--profile", "p"] not in calls
    if mode:
        assert ["list-groups", "--json", "--profile", "p"] in calls
        assert ["gateway-get-config", "--gateway-url", "https://gw:8000", "--json", "--profile", "p"] in calls


def test_export_targets_groups_gateway_hcl(tmp_path):
    r = export(tmp_path, "--hcl", "--types", "targets,groups,gateway")
    assert r.returncode == 0, r.stderr
    h = tmp_path / "hcl"
    files = _hcl_files(h)
    for f in ("targets/targets_aws-prod.tf", "groups/groups_payments-oidc-app.tf", "gateway/defaults.tf",
              "gateway/cache.tf", "gateway/remote_access.tf", "gateway/log_forwarding.tf",
              "gateway/migrations/conjur-prod.tf", "gateway/allowed_access/platform-admins.tf", "targets.tf"):
        assert f in files, f
    for f in ("targets/targets_aws-prod.json", "groups/groups_payments-oidc-app.json", "gateway/defaults.json",
              "gateway/migrations/conjur-prod.json", "gateway/allowed_access/platform-admins.json"):
        assert (tmp_path / "raw" / f).exists(), f
    aws = (h / "targets/targets_aws-prod.tf").read_text()
    assert 'region                = "eu-west-1"' in aws and 'access_key            = var.secrets["/targets/aws-prod:access_key"]' in aws
    assert "user_assignment = jsonencode(" in (h / "groups/groups_payments-oidc-app.tf").read_text()
    mig = (h / "gateway/migrations/conjur-prod.tf").read_text()
    assert 'target_location = "/conjur"' in mig and 'conjur_api_key  = var.secrets["conjur-prod:conjur_api_key"]' in mig
    assert 'host          = "siem.example.com:6514"' in (h / "gateway/log_forwarding.tf").read_text()
    assert "akeyless = akeyless.gateway" in (h / "main.tf").read_text()
    imports = (h / "imports.tf").read_text()
    for needle in ("to = module.targets.akeyless_target_aws.targets_aws_prod",
                   "to = akeyless_target_lets_encrypt.targets_letsencrypt",
                   "to = module.groups.akeyless_group.groups_payments_oidc_app",
                   "to = module.gateway.akeyless_gateway_defaults.defaults",
                   "to = module.gateway.module.migrations.akeyless_gateway_migration_conjur.conjur_prod",
                   "to = module.gateway.module.allowed_access.akeyless_gateway_allowed_access.platform_admins"):
        assert needle in imports, needle
    assert "mystery" not in imports
    report = (tmp_path / "REPORT.md").read_text()
    assert "quantum_vault" in report and "lets_encrypt` mapped to akeyless_target_lets_encrypt by name - VERIFY" in report
    assert 'alias               = "gateway"' in (h / "versions.tf").read_text()
    assert "s3cr3t" not in "".join((h / f).read_text() for f in files)


def test_export_hcl_without_details_keeps_list_layout(tmp_path):
    r = export(tmp_path, "--hcl", "--types", "targets,groups", "--no-details")
    assert r.returncode == 0, r.stderr
    files = _hcl_files(tmp_path / "hcl")
    assert "targets.tf" in files and "groups.tf" in files and not any(f.startswith(("targets/", "groups/")) for f in files)
    assert 'user_assignment = var.inputs["/groups/payments-oidc-app:user_assignment"]' in (tmp_path / "hcl/groups.tf").read_text()


@pytest.mark.parametrize("args", [["--transport", "api"],                       # no token
                                  ["--transport", "cli", "--akeyless", "/bin/false", "--types", "gateway"]])
def test_transport_errors(tmp_path, args):
    env = {k: v for k, v in os.environ.items() if k != "AKEYLESS_TOKEN"}
    r = subprocess.run([sys.executable, os.path.join(SCRIPTS, "akl_export.py"), "--out", str(tmp_path), *args],
                       capture_output=True, text=True, env=env)
    assert r.returncode == 2, r.stdout + r.stderr


# ---------- conjur ----------
def test_conjur_translation(tmp_path):
    r = run("scripts/conjur2akeyless.py", os.path.join(HERE, "fixtures/conjur.yml"), "--out", str(tmp_path),
            "--item-prefix", "/conjur")
    assert r.returncode == 0, r.stderr
    roles = yaml.safe_load(open(tmp_path / "roles/conjur.yaml"))["roles"]
    layer = roles["/governance/roles/conjur/layer-prod-payments"]
    assert {"path": "/conjur/prod/payments/db/password", "capabilities": ["list", "read"]} in layer["rules"]
    assert {"path": "/conjur/prod/payments/api-key", "capabilities": ["list", "read"]} in layer["rules"]
    grp = roles["/governance/roles/conjur/group-payments-admins"]
    assert grp["rules"] == [{"path": "/conjur/prod/payments/db/password", "capabilities": ["list", "update"]}]
    b = yaml.safe_load(open(tmp_path / "bindings.yaml"))["bindings"]
    assert b["host:prod/payments/checkout"]["akeyless_roles"] == ["/governance/roles/conjur/layer-prod-payments"]
    assert b["user:alice"]["akeyless_roles"] == ["/governance/roles/conjur/group-payments-admins"]
    assert "webservice" in open(tmp_path / "REPORT.md").read()


def test_translated_conjur_roles_pass_model_loader(tmp_path):
    run("scripts/conjur2akeyless.py", os.path.join(HERE, "fixtures/conjur.yml"), "--out", str(tmp_path))
    model = m.Model.load(str(tmp_path))
    assert len(model.roles) == 2


# ---------- watchover entry point / usage guide ----------
import re  # noqa: E402

import watchover  # noqa: E402


def test_usage_guide_is_generated_and_current():
    with open(os.path.join(REPO, "docs/usage-guide.md"), encoding="utf-8") as fh:
        assert fh.read() == watchover.render_markdown(), "run: scripts/watchover help --markdown > docs/usage-guide.md"


def test_skill_md_lists_exactly_the_skill_commands():
    skill = open(os.path.join(REPO, "skill/akeyless-watchover/SKILL.md"), encoding="utf-8").read()
    section = skill.split("## Commands", 1)[1].split("\n## ", 1)[0]
    listed = re.findall(r"^\| `([a-z-]+)` \|", section, flags=re.M)
    assert listed == [c.name for c in watchover.SKILL_COMMANDS]


@pytest.mark.parametrize("topic", [None, "skill"] + [t.name for t in watchover.TOOLS])
def test_help_topics(topic, capsys):
    assert watchover.main(["help"] + ([topic] if topic else [])) == 0
    assert capsys.readouterr().out.strip()


def test_every_tool_parameter_is_documented():
    for t in watchover.TOOLS:
        for flag, _value, _req, desc in watchover._params(t.parser()):
            assert desc, f"{t.name} {flag} has no help text"


def test_unknown_command_and_topic():
    assert watchover.main(["nope"]) == 2
    assert watchover.main(["help", "nope"]) == 2


def test_dispatch_simulate():
    assert watchover.main(["simulate", "--model", os.path.join(REPO, "terraform/model"),
                           "--expectations", os.path.join(REPO, "terraform/model/access_expectations.yaml")]) == 0


# ---------- forwarder scaffolding ----------
import akl_forwarder as fw  # noqa: E402


def _fw(*argv):
    return fw.build_entry(fw.build_parser().parse_args(list(argv)))


def test_forwarder_presets_use_only_valid_event_types():
    gov_tf = open(os.path.join(REPO, "terraform", "main.tf")).read()
    for events in fw.PRESETS.values():
        assert set(events) <= set(fw.EVENT_TYPES)
    for ev in fw.EVENT_TYPES:          # same list as the Terraform guard
        assert f'"{ev}"' in gov_tf


def test_forwarder_secrets_are_referenced_not_written():
    e, secrets = _fw("--name", "/e/sn", "--type", "service_now", "--host", "h", "--auth-type", "jwt",
                     "--client-id", "c", "--user-email", "u@x", "--event", "usage", "--items-source", "/*")
    assert secrets == ["e_sn_client_secret", "e_sn_app_private_key"]
    assert e["client_secret_var"] == "e_sn_client_secret" and "client_secret" not in e
    e, secrets = _fw("--name", "/e/s", "--type", "slack", "--event", "usage", "--items-source", "/*")
    assert e["url_var"] == "e_s_url" and "url" not in e


@pytest.mark.parametrize("argv,msg", [
    (["--type", "email", "--event", "usage", "--items-source", "/*"], "--email-to"),
    (["--type", "email", "--email-to", "a@b", "--items-source", "/*"], "--preset"),
    (["--type", "email", "--email-to", "a@b", "--event", "nope", "--items-source", "/*"], "unknown event"),
    (["--type", "email", "--email-to", "a@b", "--event", "usage"], "source"),
    (["--type", "email", "--email-to", "a@b", "--event", "usage", "--items-source", "/*", "--runner", "periodic"], "--every"),
    (["--type", "teams", "--event", "usage", "--items-source", "/*"], "--gateway-source"),
    (["--type", "webhook", "--url", "u", "--auth-type", "oauth", "--event", "usage", "--items-source", "/*"], "auth-type"),
    (["--type", "service_now", "--host", "h", "--event", "usage", "--items-source", "/*"], "user-pass|jwt"),
])
def test_forwarder_rejects_what_terraform_would_reject(argv, msg):
    with pytest.raises(ValueError, match=msg.replace("|", r"\|")):
        _fw("--name", "/e/x", *argv)


def test_forwarder_write_preserves_file_and_refuses_duplicates(tmp_path):
    gov = tmp_path / "governance.yaml"
    gov.write_text("# keep me\naccount_settings:\n  max_versions: 10\n\nevent_forwarders:\n  /e/a:\n    type: email\n"
                   "    email_to: [a@b]\n    event_types: [usage]\n\n# next section\nnaming:\n  role_prefix: /r\n")
    argv = ["--name", "/e/b", "--type", "slack", "--event", "usage", "--items-source", "/*", "--write", str(gov)]
    fw.main(argv)
    text = gov.read_text()
    doc = yaml.safe_load(text)
    assert list(doc["event_forwarders"]) == ["/e/a", "/e/b"]
    assert doc["naming"] == {"role_prefix": "/r"} and doc["account_settings"] == {"max_versions": 10}
    assert "# keep me" in text and text.index("/e/b") < text.index("# next section")
    with pytest.raises(SystemExit):
        fw.main(argv)
    assert gov.read_text() == text


def test_forwarder_import_block(capsys):
    fw.main(["--name", "/e/old", "--type", "email", "--email-to", "a@b", "--event", "usage", "--items-source", "/*",
             "--import-existing"])
    out = capsys.readouterr().out
    assert 'to = akeyless_event_forwarder_email.this["/e/old"]' in out and 'id = "/e/old"' in out


def test_forwarder_fixture_is_regenerated_unchanged(tmp_path):
    fixture = os.path.join(REPO, "terraform", "tests", "fixtures", "forwarders")
    out = tmp_path / "governance.yaml"
    subprocess.run(["bash", os.path.join(fixture, "generate.sh"), str(out)], check=True, capture_output=True)
    assert out.read_text() == open(os.path.join(fixture, "governance.yaml")).read()


# ---------- manual ----------
def test_manual_reference_parts_are_current():
    """docs/manual/generated/{commands,variables}.tex (and docs/*.tex when pandoc exists) match the code."""
    res = run(os.path.join(REPO, "docs", "manual", "build.py"), "--check")
    assert res.returncode == 0, res.stdout + res.stderr


def test_manual_has_an_example_and_session_for_every_command():
    man = os.path.join(REPO, "docs", "manual")
    import watchover as wo
    for t in wo.TOOLS:
        assert os.path.exists(os.path.join(man, "generated", "examples", t.name + ".tex")), t.name
    for c in wo.SKILL_COMMANDS:
        assert os.path.exists(os.path.join(man, "sessions", c.name + ".tex")), c.name


# ---------- agent-neutral packaging ----------
import akl_skill  # noqa: E402
import watchover_mcp  # noqa: E402


def test_skill_source_follows_the_agent_skills_spec_and_version_matches():
    import watchover as wo
    assert akl_skill.validate(akl_skill.SRC) == []
    meta, body = akl_skill.split_frontmatter(open(os.path.join(akl_skill.SRC, "SKILL.md")).read())
    assert meta["metadata"]["version"] == wo.VERSION
    # vendor-neutral: no product name in the instructions an agent follows
    for vendor in ("Claude", "ChatGPT", "Copilot", "Gemini", "Cursor", "Codex"):
        assert vendor not in body, vendor


@pytest.mark.parametrize("front,msg", [
    ("name: akeyless-watchover\ndescription: x\nversion: 1", "not in the Agent Skills specification"),
    ("name: other-name\ndescription: x", "must match the folder"),
    ("name: Bad--Name\ndescription: x", "1-64 characters"),
    ("name: akeyless-watchover\ndescription: " + "x" * 1025, "1-1024"),
    ("name: akeyless-watchover\ndescription: x\ncompatibility: " + "y" * 501, "1-500"),
    ("name: akeyless-watchover\ndescription: x\nmetadata: {version: 1}", "string values"),
])
def test_skill_validator_rejects(tmp_path, front, msg):
    d = tmp_path / "akeyless-watchover"
    d.mkdir()
    (d / "SKILL.md").write_text(f"---\n{front}\n---\nbody\n")
    assert any(msg in p for p in akl_skill.validate(str(d)))


def test_build_writes_valid_package_and_prompt_pack(tmp_path):
    res = akl_skill.build(str(tmp_path / "dist"))
    assert akl_skill.validate(res["skill"]) == []
    for rel in ("SKILL.md", "agents/openai.yaml", "references/agents.md", "references/usage-guide.md",
                "template/scripts/watchover", "template/terraform/main.tf"):
        assert os.path.exists(os.path.join(res["skill"], rel)), rel
    import zipfile
    names = zipfile.ZipFile(res["skill_zip"]).namelist()
    assert "akeyless-watchover/SKILL.md" in names and all(n.startswith("akeyless-watchover/") for n in names)
    assert not any("__pycache__" in n or ".terraform/" in n for n in names)
    pack = res["prompt_pack"]
    full = open(os.path.join(pack, "system-prompt.md")).read()
    assert not full.startswith("---") and "## Commands" in full
    assert len(open(os.path.join(pack, "system-prompt-short.md")).read()) < 3000
    assert os.path.exists(os.path.join(pack, "knowledge", "akeyless-watchover-instructions.md"))
    assert os.path.exists(os.path.join(pack, "knowledge", "references", "rbac-model.md"))


@pytest.mark.parametrize("agent,scope,suffix", [
    ("claude", "project", ".claude/skills/akeyless-watchover"),
    ("codex", "project", ".agents/skills/akeyless-watchover"),
    ("copilot", "project", ".github/skills/akeyless-watchover"),
    ("cursor", "project", ".cursor/skills/akeyless-watchover"),
    ("gemini", "project", ".gemini/skills/akeyless-watchover"),
    ("copilot", "user", ".copilot/skills/akeyless-watchover"),
])
def test_install_targets(agent, scope, suffix, tmp_path):
    assert akl_skill.target_dir(agent, scope, str(tmp_path), None).endswith(suffix)


def test_install_and_reuse_from_the_installed_copy(tmp_path):
    target = akl_skill.install("custom", "project", dest=str(tmp_path / "skills"))
    assert akl_skill.validate(target) == []
    with pytest.raises(FileExistsError):
        akl_skill.install("custom", "project", dest=str(tmp_path / "skills"))
    # the packaged kit works from inside the installed skill (no repository needed)
    kit = os.path.join(target, "template")
    res = subprocess.run([sys.executable, os.path.join(kit, "scripts", "watchover.py"), "validate-skill"],
                         capture_output=True, text=True, cwd=kit)
    assert res.returncode == 0 and target in res.stdout, res.stdout + res.stderr


# ---------- MCP server ----------
def _mcp(*messages, env=None):
    lines = "\n".join(json.dumps(m) for m in messages) + "\n"
    res = subprocess.run([sys.executable, os.path.join(SCRIPTS, "watchover_mcp.py")], input=lines,
                         capture_output=True, text=True, cwd=REPO, env={**os.environ, **(env or {})}, timeout=120)
    return {r["id"]: r for r in map(json.loads, res.stdout.splitlines())}


def _req(i, method, params=None):
    return {"jsonrpc": "2.0", "id": i, "method": method, "params": params or {}}


def test_mcp_handshake_tools_resources_prompts():
    out = _mcp(_req(1, "initialize", {"protocolVersion": "2025-06-18", "capabilities": {},
                                      "clientInfo": {"name": "t", "version": "1"}}),
               {"jsonrpc": "2.0", "method": "notifications/initialized"},
               _req(2, "tools/list"), _req(3, "resources/list"), _req(4, "prompts/list"),
               _req(5, "tools/call", {"name": "watchover_simulate",
                                      "arguments": {"model": "terraform/model",
                                                    "expectations": "terraform/model/access_expectations.yaml"}}),
               _req(6, "resources/read", {"uri": "watchover://skill/SKILL.md"}),
               _req(7, "prompts/get", {"name": "watchover-change", "arguments": {"request": "give team x read"}}),
               _req(8, "nope"), _req(9, "tools/call", {"name": "watchover_verify", "arguments": {}}))
    init = out[1]["result"]
    assert init["protocolVersion"] == "2025-06-18" and init["serverInfo"]["name"] == "watchover-mcp"
    tools = {t["name"]: t for t in out[2]["result"]["tools"]}
    assert "watchover_simulate" in tools and "watchover_verify" not in tools and "watchover_mcp" not in tools
    fw = tools["watchover_forwarder"]["inputSchema"]
    assert fw["properties"]["event"]["type"] == "array" and "name" in fw["required"]
    assert fw["properties"]["type"]["enum"] == ["email", "webhook", "slack", "teams", "service_now"]
    assert "watchover://docs/agents.md" in {r["uri"] for r in out[3]["result"]["resources"]}
    assert {p["name"] for p in out[4]["result"]["prompts"]} >= {"watchover-design", "watchover-change"}
    call = out[5]["result"]
    assert call["isError"] is False and "0 mismatch(es)" in call["content"][0]["text"]
    assert out[6]["result"]["contents"][0]["text"].startswith("---\nname: akeyless-watchover")
    msg = out[7]["result"]["messages"][0]["content"]["text"]
    assert "give team x read" in msg and "<skill-instructions>" in msg
    assert out[8]["error"]["code"] == -32601 and out[9]["error"]["code"] == -32602


def test_mcp_live_tools_are_opt_in_and_arguments_map_to_options():
    out = _mcp(_req(1, "tools/list"), env={"WATCHOVER_MCP_LIVE": "1"})
    names = {t["name"] for t in out[1]["result"]["tools"]}
    assert {"watchover_verify", "watchover_export", "watchover_account_settings", "watchover_token"} <= names
    import argparse as _ap
    p = dict((n, pr) for n, _s, pr, _l in watchover_mcp.exposed_tools())["forwarder"]
    argv = watchover_mcp.to_argv(p, {"name": "/e/x", "type": "email", "event": ["usage", "usage-report"],
                                     "disabled": True, "every": 6})
    assert argv == ["--name", "/e/x", "--type", "email", "--event", "usage", "--event", "usage-report",
                    "--every", "6", "--disabled"]
    with pytest.raises(ValueError):
        watchover_mcp.to_argv(p, {"bogus": 1})
    assert isinstance(p, _ap.ArgumentParser)


def test_mcp_tool_errors_are_reported_not_raised():
    out = _mcp(_req(1, "tools/call", {"name": "watchover_forwarder",
                                      "arguments": {"name": "/e/x", "type": "teams", "event": ["usage"],
                                                    "items_source": ["/*"]}}))
    r = out[1]["result"]
    assert r["isError"] is True and "gateway-source" in r["content"][0]["text"]


def test_every_command_documents_how_it_works_and_exit_codes():
    import watchover as wo
    assert {c.name for c in wo.SKILL_COMMANDS} == set(wo.SKILL_HOW)
    assert {t.name for t in wo.TOOLS} == set(wo.TOOL_HOW) == set(wo.TOOL_EXITS)


# ---------- reconcile (read-only repository comparison) ----------
import akl_reconcile as rec  # noqa: E402

FX_EXPORT = os.path.join(HERE, "fixtures", "export")


def test_reconcile_yaml_edit_keeps_the_rest_of_the_file():
    text = ("# header comment\nroles:\n  /r/a:\n    rules: []   # keep\n\n  # about b\n  /r/b:\n    description: x\n"
            "\nnaming: {}\n")
    new = rec.edit_yaml(text, "roles", "/r/b", {"description": "y"})
    assert new.startswith("# header comment\nroles:\n  /r/a:\n    rules: []   # keep\n\n  # about b\n")
    assert yaml.safe_load(new)["roles"]["/r/b"] == {"description": "y"} and new.endswith("\nnaming: {}\n")
    added = rec.edit_yaml(new, "roles", "/r/c", {"rules": []})
    assert list(yaml.safe_load(added)["roles"]) == ["/r/a", "/r/b", "/r/c"] and "naming: {}" in added
    removed = rec.edit_yaml(added, "roles", "/r/a", None)
    assert list(yaml.safe_load(removed)["roles"]) == ["/r/b", "/r/c"] and "# header comment" in removed
    fresh = rec.edit_yaml("# only a comment\n", "folders", "/x", {"description": "d"})
    assert yaml.safe_load(fresh) == {"folders": {"/x": {"description": "d"}}}


def test_reconcile_normalisation_ignores_noise():
    model = {"rules": [{"path": "/a/*", "capabilities": ["read", "list"], "type": "item-rule"}],
             "associations": [{"auth_method": "/am", "case_sensitive": True, "sub_claims": {"groups": "g1,g2"}}],
             "allow_external_auth_methods": True, "audit_access": "none", "delete_protection": "false",
             "client_secret_var": "x"}
    live = {"rules": [{"path": "/a/*", "capabilities": ["list", "read"]}],
            "associations": [{"auth_method": "/am", "sub_claims": {"groups": ["g2", "g1"]}}]}
    assert rec.compare("roles", model, live) == {"changed": {}, "only_akeyless": {}, "only_model": {}}


def test_git_wrapper_refuses_to_write():
    for verb in ("push", "commit", "merge", "rebase", "reset", "tag"):
        with pytest.raises(RuntimeError, match="read-only"):
            rec.git(verb, "origin")
    src = open(os.path.join(SCRIPTS, "akl_reconcile.py")).read()
    assert not re.search(r'git\("(push|commit|merge|rebase|reset|tag)"', src)


def _ghe(tmp_path):
    """A bare repository standing in for GitHub Enterprise, seeded with a model that drifted from the fixtures."""
    ex = tmp_path / "ex"
    import akl_export
    akl_export._main(["--out", str(ex), "--from-dir", FX_EXPORT, "--types", rec.EXPORT_TYPES])
    seed = tmp_path / "seed"
    (seed / "terraform/model/roles").mkdir(parents=True)
    for src, dst in (("auth_methods.imported.yaml", "auth_methods.yaml"), ("folders.imported.yaml", "folders.yaml"),
                     ("governance.imported.yaml", "governance.yaml")):
        (seed / "terraform/model" / dst).write_text((ex / "model" / src).read_text())
    roles = yaml.safe_load((ex / "model/roles/imported.yaml").read_text())
    roles["roles"]["/governance/roles/payments/team-admin"]["rules"][0]["capabilities"] = ["list", "read"]
    del roles["roles"]["/governance/roles/platform/god"]
    roles["roles"]["/governance/roles/payments/old"] = {"rules": [{"path": "/old/*", "capabilities": ["read"]}]}
    (seed / "terraform/model/roles/payments.yaml").write_text("# payments team\n" + yaml.safe_dump(roles, sort_keys=False))
    g = ["git", "-c", "user.email=t@t", "-c", "user.name=t"]
    for cmd in (["git", "init", "-q", "-b", "main", "."], ["git", "add", "-A"], g + ["commit", "-qm", "seed"]):
        subprocess.run(cmd, cwd=seed, check=True)
    bare = tmp_path / "ghe.git"
    subprocess.run(["git", "clone", "-q", "--bare", str(seed), str(bare)], check=True)
    return bare


def test_reconcile_against_a_remote_repository(tmp_path):
    bare = _ghe(tmp_path)
    head = subprocess.run(["git", "rev-parse", "HEAD"], cwd=bare, capture_output=True, text=True).stdout
    out = tmp_path / "rec"
    with pytest.raises(SystemExit) as e:
        rec.main(["--repo-url", f"file://{bare}", "--from-dir", FX_EXPORT, "--out", str(out)])
    assert e.value.code == 1
    s = json.loads((out / "summary.json").read_text())
    assert s["counts"] == {"different": 1, "only_akeyless": 1, "only_model": 1}
    assert s["repository"]["commit"] == head.strip()
    report = (out / "REPORT.md").read_text()
    assert "Nothing was committed or pushed" in report and "/governance/roles/payments/old" in report
    assert (out / "proposed/terraform/model/roles/payments.yaml").read_text().startswith("# payments team\n")
    assert "akeyless_role.this[\"/governance/roles/platform/god\"]" in (out / "imports.tf").read_text()
    # the patch applies cleanly to a fresh clone; the remote is untouched
    wc = tmp_path / "wc"
    subprocess.run(["git", "clone", "-q", str(bare), str(wc)], check=True)
    subprocess.run(["git", "apply", str(out / "changes.patch")], cwd=wc, check=True)
    assert yaml.safe_load((wc / "terraform/model/roles/payments.yaml").read_text())["roles"][
        "/governance/roles/payments/team-admin"]["rules"][0]["capabilities"] == ["create", "list", "read"]
    assert subprocess.run(["git", "rev-parse", "HEAD"], cwd=bare, capture_output=True, text=True).stdout == head


def test_reconcile_clone_cannot_push_and_local_checkout_is_not_modified(tmp_path):
    bare = _ghe(tmp_path)
    clone = tmp_path / "clone"
    rec.fetch_repo(f"file://{bare}", "main", str(clone))
    push = subprocess.run(["git", "remote", "get-url", "--push", "origin"], cwd=clone, capture_output=True, text=True)
    assert push.stdout.strip() == rec.NO_PUSH_URL
    before = subprocess.run(["git", "status", "--porcelain"], cwd=clone, capture_output=True, text=True).stdout
    with pytest.raises(SystemExit):
        rec.main(["--repo-dir", str(clone), "--from-dir", FX_EXPORT, "--out", str(tmp_path / "rec"), "--propose-removals"])
    after = subprocess.run(["git", "status", "--porcelain"], cwd=clone, capture_output=True, text=True).stdout
    assert before == after == ""
    s = json.loads((tmp_path / "rec/summary.json").read_text())
    assert any(r.get("proposed") == ["remove"] for r in s["results"])


def test_reconcile_no_differences_exits_zero(tmp_path):
    import akl_export
    ex = tmp_path / "ex"
    akl_export._main(["--out", str(ex), "--from-dir", FX_EXPORT, "--types", rec.EXPORT_TYPES])
    repo = tmp_path / "repo/terraform/model"
    (repo / "roles").mkdir(parents=True)
    (repo / "roles/all.yaml").write_text((ex / "model/roles/imported.yaml").read_text())
    for src, dst in (("auth_methods.imported.yaml", "auth_methods.yaml"), ("folders.imported.yaml", "folders.yaml"),
                     ("governance.imported.yaml", "governance.yaml")):
        (repo / dst).write_text((ex / "model" / src).read_text())
    with pytest.raises(SystemExit) as e:
        rec.main(["--repo-dir", str(tmp_path / "repo"), "--export-dir", str(ex), "--out", str(tmp_path / "rec")])
    assert e.value.code == 0
    assert "No differences" in (tmp_path / "rec/REPORT.md").read_text()


# ---------- pagination: the last page is the first EMPTY page ----------
class _PagedSource:
    def __init__(self, pages):
        self.pages, self.calls = pages, []

    def __call__(self, op, params):
        self.calls.append(params.get("pagination-token"))
        return self.pages(params.get("pagination-token"))


def _paged(pages, max_pages=None):
    import akl_export
    src = akl_export._Source()
    fake = _PagedSource(pages)
    src.request = lambda op, p=None, allow_fail=False: fake(op, p or {})
    if max_pages:
        src.MAX_PAGES = max_pages
    return src._paged("list-roles", "roles"), fake.calls


@pytest.mark.parametrize("name,pages,want,calls", [
    ("token on every page, last page empty",
     lambda t: {"roles": [{"n": t or "p0"}] if (t or "p0") in ("p0", "p1") else [], "next_page": f"p{int((t or 'p0')[1:]) + 1}"},
     2, 3),
    ("token missing on the last page", lambda t: {"roles": [{"n": t or "p0"}], **({"next_page": "p1"} if not t else {})}, 2, 2),
    ("token repeats", lambda t: {"roles": [{"n": t or "p0"}], "next_page": "p1"}, 2, 2),
    ("server ignores the token (same rows again)", lambda t: {"roles": [{"n": 1}], "next_page": "x" + str(t)}, 1, 2),
    ("first page empty", lambda t: {"roles": [], "next_page": "p1"}, 0, 1),
])
def test_pagination_stops(name, pages, want, calls):
    rows, made = _paged(pages)
    assert len(rows) == want and len(made) == calls, name


def test_pagination_never_loops_forever():
    with pytest.raises(RuntimeError, match="pages"):
        _paged(lambda t: {"roles": [{"n": t}], "next_page": f"{t}x"}, max_pages=50)
