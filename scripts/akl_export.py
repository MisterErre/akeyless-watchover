#!/usr/bin/env python3
"""Brownfield export: turn an existing Akeyless account into the YAML model + import blocks.

Reads roles and auth methods with the CLI (or from saved JSON with --from-dir) and writes:
  <out>/model/roles/imported.yaml          roles, rules, management-plane access, associations
  <out>/model/auth_methods.imported.yaml   auth methods: type + common settings (type-specific
                                           bound_* settings are left as TODO - see raw/)
  <out>/imports.tf                          Terraform/OpenTofu import blocks for the addresses
                                           used by terraform/*.tf
  <out>/raw/                                every JSON document read (for manual completion)
  <out>/REPORT.md                           what needs a human decision

Then: review, move the files into terraform/model/, add imports.tf to terraform/, and run
`terraform plan` until it shows no changes (import only, nothing to create/destroy).

Usage:
  python3 scripts/akl_export.py --out export/ [--profile admin] [--exclude '^/governance/roles/platform/terraform-']
  python3 scripts/akl_export.py --out export/ --from-dir saved/   # offline: saved/roles/*.json, saved/auth_methods/*.json
"""
from __future__ import annotations

import argparse
import glob
import json
import os
import re
import subprocess
import sys

import yaml

# access-rule types stored as role rules by the API -> role attributes (provider 2.0.5 mapping)
ACCESS_RULES = {
    "search-rule": "audit_access", "reports-rule": "analytics_access", "gw-reports-rule": "gw_analytics_access",
    "sra-reports-rule": "sra_reports_access", "usage-reports-rule": "usage_reports_access",
    "event-rule": "event_center_access", "event-forwarder-rule": "event_forwarders_access",
    "isi-rule": "isi_access", "unlock-secrets-rule": "unlock_secrets",
    "approve-access-request-rule": "approve_access_request",
}
ACCESS_PATH = {"/*": "all", "/self": "own", "/scoped": "scoped"}
RULE_TYPES = {"item-rule", "target-rule", "role-rule", "auth-method-rule", "sra-rule", "ara-rule"}
# capability names the API returns for SRA rules -> names used in configuration (provider mapping)
SRA_CAPS = {"sra_transparently_connect": "allow_access", "sra_request_for_access": "request_access",
            "sra_require_justification": "justify_access_only", "sra_approval_authority": "approval_authority",
            "sra_upload_files": "upload_files", "sra_download_files": "download_files"}
AM_TYPES = {"api_key", "oidc", "saml", "oauth2", "aws_iam", "azure_ad", "k8s", "universal_identity"}


class Cli:
    def __init__(self, binary: str, profile: str | None):
        self.binary, self.profile = binary, profile

    def json(self, *args: str) -> dict:
        cmd = [self.binary, *args, "--json"] + (["--profile", self.profile] if self.profile else [])
        res = subprocess.run(cmd, capture_output=True, text=True)
        if res.returncode != 0:
            raise RuntimeError(f"{' '.join(cmd)}: {(res.stderr or res.stdout).strip()}")
        return json.loads(res.stdout or "{}")

    def list_all(self, command: str, key: str) -> list[dict]:
        out, token = [], None
        while True:
            data = self.json(command, *(["--pagination-token", token] if token else []))
            out += data.get(key) or []
            token = data.get("next_page")
            if not token:
                return out


def tf_key(s: str) -> str:
    return json.dumps(s)  # HCL string literal with escaping


def convert_role(role: dict, report: list[str]) -> dict:
    name = role["role_name"]
    r: dict = {}
    if role.get("description") or role.get("comment"):
        r["description"] = role.get("description") or role.get("comment")
    if str(role.get("delete_protection", "")).lower() == "true":
        r["delete_protection"] = True
    rules = []
    for pr in ((role.get("rules") or {}).get("path_rules") or []):
        rtype, path, caps = pr.get("type"), pr.get("path"), list(pr.get("capabilities") or [])
        if rtype in ACCESS_RULES:
            attr = ACCESS_RULES[rtype]
            if path in ACCESS_PATH:
                r[attr] = ACCESS_PATH[path]
            elif rtype == "event-forwarder-rule":
                r.setdefault("event_forwarders_name", []).append(path)
            else:
                report.append(f"- role `{name}`: access rule {rtype} with unexpected path `{path}` - review")
            continue
        if rtype not in RULE_TYPES:
            report.append(f"- role `{name}`: rule type `{rtype}` on `{path}` is not handled by the model - review")
            continue
        if pr.get("ttl"):
            report.append(f"- role `{name}`: temporary rule on `{path}` (ttl) skipped - temporary rules are CLI-only")
            continue
        if rtype == "sra-rule":
            caps = [SRA_CAPS.get(c, c) for c in caps]
        rule = {"path": path, "capabilities": sorted(caps)}
        if rtype != "item-rule":
            rule["type"] = rtype
        rules.append(rule)
        if path in ("/*", "/") and set(caps) - {"list", "deny"} and not (
                rtype in ("role-rule", "auth-method-rule") and set(caps) <= {"list", "read", "deny"}):
            r["allow_root_scope"] = True
            report.append(f"- role `{name}`: root-scope rule `{rtype} {path} {caps}` - confirm it is intended")
    r["rules"] = rules
    assocs = []
    for a in role.get("role_auth_methods_assoc") or []:
        entry = {"auth_method": a.get("auth_method_name")}
        sc = a.get("auth_method_sub_claims") or {}
        if sc:
            entry["sub_claims"] = {k: (v if isinstance(v, list) else [v]) for k, v in sc.items()}
        if a.get("sub_claims_case_sensitive") is False:
            entry["case_sensitive"] = False
        if a.get("is_subclaims_with_operator"):
            report.append(f"- role `{name}` <- `{entry['auth_method']}`: sub-claims use AND/OR operators - check the exported value")
        assocs.append(entry)
    if assocs:
        r["associations"] = assocs
    return r


def convert_am(am: dict, report: list[str]) -> dict:
    name = am["auth_method_name"]
    info = am.get("access_info") or {}
    raw_type = str(info.get("rules_type") or "")
    norm = raw_type.lower().replace("-", "_")
    norm = {"jwt": "oauth2", "oauth": "oauth2", "apikey": "api_key", "universal_identity": "universal_identity"}.get(norm, norm)
    a: dict = {"type": norm if norm in AM_TYPES else f"TODO-unsupported-{raw_type or 'unknown'}"}
    if a["type"].startswith("TODO"):
        report.append(f"- auth method `{name}`: type `{raw_type}` is not modelled - manage it outside the model or extend auth_methods.tf")
    if am.get("description"):
        a["description"] = am["description"]
    if info.get("access_expires"):
        a["access_expires"] = info["access_expires"]
    if info.get("cidr_whitelist"):
        a["bound_ips"] = [c.strip() for c in str(info["cidr_whitelist"]).split(",") if c.strip()]
    if info.get("gw_cidr_whitelist"):
        a["gw_bound_ips"] = [c.strip() for c in str(info["gw_cidr_whitelist"]).split(",") if c.strip()]
    for k in ("force_sub_claims", "jwt_ttl", "audit_logs_claims", "allowed_client_type"):
        if info.get(k) not in (None, [], ""):
            a[k] = info[k]
    if str(am.get("delete_protection", "")).lower() == "true":
        a["delete_protection"] = True
    if a["type"] not in ("api_key", "universal_identity") and not a["type"].startswith("TODO"):
        a["TODO"] = "add the type-specific settings (issuer, bound_*, unique_identifier...) from raw/auth_methods"
        report.append(f"- auth method `{name}` ({a['type']}): complete type-specific settings from raw/ before planning")
    return a


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--out", required=True, help="output directory (model/, imports.tf, raw/, REPORT.md)")
    ap.add_argument("--profile", help="akeyless CLI profile with read access to all roles and auth methods")
    ap.add_argument("--akeyless", default="akeyless", help="path to the akeyless CLI binary")
    ap.add_argument("--from-dir", help="read saved JSON (roles/*.json, auth_methods/*.json) instead of calling the CLI")
    ap.add_argument("--exclude", action="append", default=[], help="regex of role/auth-method names to skip (repeatable)")
    return ap


def main(argv: list[str] | None = None) -> None:
    a = build_parser().parse_args(argv)
    excl = [re.compile(x) for x in a.exclude]
    skip = lambda n: any(x.search(n) for x in excl)  # noqa: E731

    if a.from_dir:
        roles = [json.load(open(f)) for f in sorted(glob.glob(os.path.join(a.from_dir, "roles", "*.json")))]
        ams = [json.load(open(f)) for f in sorted(glob.glob(os.path.join(a.from_dir, "auth_methods", "*.json")))]
    else:
        cli = Cli(a.akeyless, a.profile)
        roles = [cli.json("get-role", "--name", r["role_name"]) for r in cli.list_all("list-roles", "roles")]
        ams = [cli.json("get-auth-method", "--name", m["auth_method_name"])
               for m in cli.list_all("list-auth-methods", "auth_methods")]

    os.makedirs(os.path.join(a.out, "raw", "roles"), exist_ok=True)
    os.makedirs(os.path.join(a.out, "raw", "auth_methods"), exist_ok=True)
    os.makedirs(os.path.join(a.out, "model", "roles"), exist_ok=True)
    report: list[str] = []
    model_roles, model_ams, imports = {}, {}, []

    for am in ams:
        n = am["auth_method_name"]
        json.dump(am, open(os.path.join(a.out, "raw", "auth_methods", re.sub(r"[^A-Za-z0-9_.-]", "_", n.strip("/")) + ".json"), "w"), indent=2)
        if skip(n):
            continue
        model_ams[n] = convert_am(am, report)
        t = model_ams[n]["type"]
        if not t.startswith("TODO"):
            imports.append(f"import {{\n  to = akeyless_auth_method_{t}.this[{tf_key(n)}]\n  id = {tf_key(n)}\n}}\n")

    for role in roles:
        n = role["role_name"]
        json.dump(role, open(os.path.join(a.out, "raw", "roles", re.sub(r"[^A-Za-z0-9_.-]", "_", n.strip("/")) + ".json"), "w"), indent=2)
        if skip(n):
            continue
        model_roles[n] = convert_role(role, report)
        imports.append(f"import {{\n  to = akeyless_role.this[{tf_key(n)}]\n  id = {tf_key(n)}\n}}\n")
        for assoc in model_roles[n].get("associations", []):
            am = assoc["auth_method"]
            if am not in model_ams:
                model_roles[n]["allow_external_auth_methods"] = True
                report.append(f"- role `{n}` is associated with `{am}`, which is not exported (excluded or unsupported)")
            imports.append(f"import {{\n  to = akeyless_associate_role_auth_method.this[{tf_key(n + '|' + am)}]\n  id = {tf_key(n + ':' + am)}\n}}\n")

    with open(os.path.join(a.out, "model", "roles", "imported.yaml"), "w") as fh:
        yaml.safe_dump({"roles": model_roles}, fh, sort_keys=True, width=140)
    with open(os.path.join(a.out, "model", "auth_methods.imported.yaml"), "w") as fh:
        yaml.safe_dump({"auth_methods": model_ams}, fh, sort_keys=True, width=140)
    with open(os.path.join(a.out, "imports.tf"), "w") as fh:
        fh.write("# Generated by scripts/akl_export.py - remove after the first successful apply.\n\n" + "\n".join(imports))
    with open(os.path.join(a.out, "REPORT.md"), "w") as fh:
        fh.write(f"# Export report\n\nroles: {len(model_roles)}, auth methods: {len(model_ams)}, import blocks: {len(imports)}\n\n"
                 + ("\n".join(report) if report else "Nothing needs review.") + "\n")
    print(f"exported {len(model_roles)} roles, {len(model_ams)} auth methods; {len(report)} item(s) in REPORT.md")


if __name__ == "__main__":
    try:
        main()
    except RuntimeError as e:
        print(f"error: {e}", file=sys.stderr)
        sys.exit(2)
