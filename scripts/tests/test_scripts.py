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
def test_export_offline(tmp_path):
    r = run("scripts/akl_export.py", "--out", str(tmp_path), "--from-dir", os.path.join(HERE, "fixtures/export"),
            "--exclude", "^/governance/auth/ci-terraform$")
    assert r.returncode == 0, r.stderr
    roles = yaml.safe_load(open(tmp_path / "model/roles/imported.yaml"))["roles"]
    team = roles["/governance/roles/payments/team-admin"]
    assert team["audit_access"] == "scoped" and team["analytics_access"] == "all"
    assert {"path": "/srv/*", "capabilities": ["allow_access"], "type": "sra-rule"} in team["rules"]
    assert not any(ru["path"] == "/payments/tmp" for ru in team["rules"])  # ttl rule skipped
    assert not any(ru["path"] == "/x" for ru in team["rules"])  # unknown type skipped
    assert team["associations"][0] == {"auth_method": "/governance/auth/sso", "sub_claims": {"groups": ["grp-a", "grp-b"]}, "case_sensitive": False}
    assert team["allow_external_auth_methods"] is True  # ci-terraform excluded
    assert roles["/governance/roles/platform/god"]["allow_root_scope"] is True
    ams = yaml.safe_load(open(tmp_path / "model/auth_methods.imported.yaml"))["auth_methods"]
    assert ams["/governance/auth/sso"]["bound_ips"] == ["10.0.0.0/8", "192.168.0.0/16"]
    assert ams["/legacy/kerb"]["type"].startswith("TODO")
    assert "/governance/auth/ci-terraform" not in ams
    imports = open(tmp_path / "imports.tf").read()
    assert 'to = akeyless_auth_method_oidc.this["/governance/auth/sso"]' in imports
    assert 'id = "/governance/roles/payments/team-admin:/governance/auth/sso"' in imports
    assert "kerb" not in imports
    report = open(tmp_path / "REPORT.md").read()
    assert "brand-new-rule" in report and "temporary rule" in report


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
