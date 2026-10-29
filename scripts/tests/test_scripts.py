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


def test_export_hcl_mode(tmp_path):
    r = export(tmp_path, "--hcl")
    assert r.returncode == 0, r.stderr
    imports = open(tmp_path / "hcl/imports.tf").read()
    assert imports.count("import {") == 21  # 18 + 2 targets with a known resource + 1 group (gateway not in default types)
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
    assert ["list-roles", "--pagination-token", "p2", "--json", "--profile", "p"] in calls
    if mode:
        assert ["list-groups", "--json", "--profile", "p"] in calls
        assert ["gateway-get-config", "--gateway-url", "https://gw:8000", "--json", "--profile", "p"] in calls


def test_export_targets_groups_gateway_hcl(tmp_path):
    r = export(tmp_path, "--hcl", "--types", "targets,groups,gateway")
    assert r.returncode == 0, r.stderr
    imports = open(tmp_path / "hcl/imports.tf").read()
    for needle in ("to = akeyless_target_aws.targets_aws_prod", "to = akeyless_target_lets_encrypt.targets_letsencrypt",
                   "to = akeyless_group.groups_payments_oidc_app",
                   "to       = akeyless_gateway_defaults.gateway_defaults\n  provider = akeyless.gateway",
                   "akeyless_gateway_cache.gateway_cache", "akeyless_gateway_remote_access.gateway_remote_access",
                   "to       = akeyless_gateway_log_forwarding_syslog.log_forwarding",
                   "to       = akeyless_gateway_migration_conjur.conjur_prod",
                   "to       = akeyless_gateway_allowed_access.platform_admins"):
        assert needle in imports, needle
    assert "mystery" not in imports
    report = open(tmp_path / "REPORT.md").read()
    assert "quantum_vault" in report and "lets_encrypt` mapped to akeyless_target_lets_encrypt by name - VERIFY" in report
    assert 'alias               = "gateway"' in open(tmp_path / "hcl/providers.tf").read()


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
