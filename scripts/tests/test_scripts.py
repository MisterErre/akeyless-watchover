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
    for needle in ("brand-new-rule", "temporary rule", "client secret not exported", "PKI issuer", "4 discovered"):
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


def test_export_hcl_mode(tmp_path):
    r = export(tmp_path, "--hcl")
    assert r.returncode == 0, r.stderr
    imports = open(tmp_path / "hcl/imports.tf").read()
    assert imports.count("import {") == 18
    for needle in ("to = akeyless_auth_method_kerberos.legacy_kerb", "to = akeyless_pki_cert_issuer.pki_issuers_payments_server",
                   "to = akeyless_account_settings.account_settings", "to = akeyless_policy_keys.payments\n",
                   'id = "/governance/roles/payments/team-admin:/governance/auth/ci-terraform"'):
        assert needle in imports, needle
    assert "api_gateway_address" in open(tmp_path / "hcl/providers.tf").read()
    assert not (tmp_path / "imports.tf").exists()


@pytest.mark.parametrize("args", [["--types", "secrets"], ["--generate"], ["--persona-claim", "a=b"],
                                  ["--persona-auth-method", "/x", "--persona-claim", "novalue"]])
def test_export_usage_errors(tmp_path, args):
    assert export(tmp_path, *args).returncode == 2


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
