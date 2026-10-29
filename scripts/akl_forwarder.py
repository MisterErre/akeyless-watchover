#!/usr/bin/env python3
"""Scaffold Terraform configuration for Akeyless event forwarders.

Akeyless has no operation that lists event forwarders, so they can't be exported. This command
writes new ones instead, already validated against the same rules the Terraform guards enforce:

  * model entry for terraform/model/governance.yaml (default; --write inserts it in place)
  * plain HCL resource block (--format hcl) for repositories that don't use the YAML model
  * an import block (--import-existing) to bring an EXISTING forwarder whose name you know under
    Terraform: the provider imports event forwarders by name

Secrets (webhook passwords/tokens/certificates, Slack/Teams URLs, ServiceNow credentials) are
never written: the output references a *_var key you then provide in TF_VAR_event_forwarder_secrets.

Examples:
  watchover forwarder --name /governance/events/secops-mail --type email --email-to secops@example.com \\
      --preset critical --items-source '/*'
  watchover forwarder --name /governance/events/pki-slack --type slack --preset certificates \\
      --items-source '/pki/*' --write terraform/model/governance.yaml
  watchover forwarder --name /governance/events/siem --type webhook --url https://siem.example.com/akeyless \\
      --auth-type bearer-token --preset critical --auth-method-source '/*' --format hcl
  watchover forwarder --name /governance/events/old-mail --type email --email-to a@b.c --event certificate-expired \\
      --import-existing
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys

import yaml

TYPES = ["email", "webhook", "slack", "teams", "service_now"]

# Event types accepted by provider 2.0.5 (identical list in terraform/main.tf local.event_types)
EVENT_TYPES = ["request-access", "certificate-pending-expiration", "certificate-expired",
               "certificate-provisioning-success", "certificate-provisioning-failure",
               "auth-method-pending-expiration", "auth-method-expired", "next-automatic-rotation",
               "rotated-secret-success", "rotated-secret-failure", "dynamic-secret-failure", "multi-auth-failure",
               "uid-rotation-failure", "apply-justification", "email-auth-method-approved", "usage", "rotation-usage",
               "gateway-inactive", "static-secret-updated", "rate-limiting", "usage-report", "secret-sync"]

# Convenience groupings of the event types above (the grouping is this kit's, the names are Akeyless')
PRESETS = {
    "certificates": ["certificate-pending-expiration", "certificate-expired", "certificate-provisioning-success",
                     "certificate-provisioning-failure"],
    "auth-methods": ["auth-method-pending-expiration", "auth-method-expired", "multi-auth-failure",
                     "uid-rotation-failure"],
    "rotation": ["next-automatic-rotation", "rotated-secret-success", "rotated-secret-failure", "rotation-usage"],
    "secrets": ["dynamic-secret-failure", "static-secret-updated", "secret-sync"],
    "access-requests": ["request-access", "apply-justification", "email-auth-method-approved"],
    "operations": ["gateway-inactive", "rate-limiting", "usage", "usage-report"],
    "critical": ["certificate-expired", "certificate-provisioning-failure", "auth-method-expired",
                 "rotated-secret-failure", "dynamic-secret-failure", "multi-auth-failure", "uid-rotation-failure",
                 "gateway-inactive"],
}

RESOURCE = {t: f"akeyless_event_forwarder_{t}" for t in TYPES}


def slug(name: str) -> str:
    return re.sub(r"[^a-z0-9]+", "_", name.strip("/").lower()).strip("_")


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--name", required=True, help="forwarder name, e.g. /governance/events/secops-mail")
    ap.add_argument("--type", required=True, choices=TYPES, help="forwarder type")
    ap.add_argument("--description", help="description")
    ap.add_argument("--preset", action="append", default=[], choices=sorted(PRESETS),
                    help="add a group of event types (repeatable); the events of each preset are listed under 'How it works'")
    ap.add_argument("--event", action="append", default=[], help="add one event type (repeatable)")
    ap.add_argument("--items-source", action="append", default=[], help="item path pattern to watch, e.g. '/pki/*' (repeatable)")
    ap.add_argument("--targets-source", action="append", default=[], help="target path pattern to watch (repeatable)")
    ap.add_argument("--auth-method-source", action="append", default=[], help="auth method path pattern to watch (repeatable)")
    ap.add_argument("--gateway-source", action="append", default=[], help="Gateway cluster URL to watch (repeatable; required for teams)")
    ap.add_argument("--runner", choices=["immediate", "periodic"], default="immediate", help="send at once or as a periodic digest")
    ap.add_argument("--every", type=int, help="hours between digests (required with --runner periodic)")
    ap.add_argument("--disabled", action="store_true", help="create it disabled")
    ap.add_argument("--key", help="protection key for the forwarder's secret (default: account key)")
    # type-specific
    ap.add_argument("--email-to", action="append", default=[], help="email: recipient (repeatable)")
    ap.add_argument("--include-error", action="store_true", help="email: include error details")
    ap.add_argument("--override-url", help="email: Gateway URL used in links (port 18888)")
    ap.add_argument("--url", help="webhook: URL (slack/teams URLs are secrets and go in the secrets map)")
    ap.add_argument("--auth-type", help="webhook: user-pass|bearer-token|certificate; service_now: user-pass|jwt")
    ap.add_argument("--username", help="webhook: user for user-pass")
    ap.add_argument("--host", help="service_now: instance host")
    ap.add_argument("--admin-name", help="service_now: admin name (user-pass)")
    ap.add_argument("--client-id", help="service_now: client ID (jwt)")
    ap.add_argument("--user-email", help="service_now: user email (jwt)")
    # output
    ap.add_argument("--format", choices=["yaml", "hcl"], default="yaml", help="model entry (yaml) or plain resource (hcl)")
    ap.add_argument("--write", metavar="GOVERNANCE_YAML", help="yaml: insert the entry into this governance.yaml")
    ap.add_argument("--import-existing", action="store_true",
                    help="the forwarder already exists in Akeyless: also print the import block (import ID = name)")
    return ap


def build_entry(a) -> tuple[dict, list[str]]:
    """Return (model entry, secrets the user must provide). Raises ValueError on invalid input."""
    events = []
    for p in a.preset:
        events += PRESETS[p]
    events += a.event
    events = list(dict.fromkeys(events))
    if not events:
        raise ValueError("choose events with --preset and/or --event")
    unknown = [e for e in events if e not in EVENT_TYPES]
    if unknown:
        raise ValueError(f"unknown event type(s) {unknown}; valid: {', '.join(EVENT_TYPES)}")
    if not a.name.startswith("/") or a.name.endswith("/"):
        raise ValueError("--name must be absolute (leading '/') and must not end with '/'")
    if a.runner == "periodic" and not a.every:
        raise ValueError("--runner periodic needs --every <hours>")
    if not (a.items_source or a.targets_source or a.auth_method_source or a.gateway_source):
        raise ValueError("choose at least one source (--items-source, --targets-source, --auth-method-source, --gateway-source)")

    s = slug(a.name)
    e: dict = {"type": a.type}
    if a.description:
        e["description"] = a.description
    e["event_types"] = events
    e["runner_type"] = a.runner
    if a.every:
        e["every"] = a.every
    if a.disabled:
        e["enable"] = False
    if a.items_source:
        e["items_event_source_locations"] = a.items_source
    if a.targets_source:
        e["targets_event_source_locations"] = a.targets_source
    if a.auth_method_source:
        e["auth_methods_event_source_locations"] = a.auth_method_source
    if a.gateway_source:
        e["gateway_event_source_locations" if a.type == "teams" else "gateways_event_source_locations"] = a.gateway_source
    if a.key:
        e["key"] = a.key
    secrets: list[str] = []

    if a.type == "email":
        if not a.email_to:
            raise ValueError("email needs --email-to")
        e["email_to"] = a.email_to
        if a.include_error:
            e["include_error"] = True
        if a.override_url:
            e["override_url"] = a.override_url
    elif a.type == "webhook":
        if not a.url:
            raise ValueError("webhook needs --url")
        e["url"] = a.url
        if a.auth_type:
            if a.auth_type not in ("user-pass", "bearer-token", "certificate"):
                raise ValueError("webhook --auth-type must be user-pass, bearer-token or certificate")
            e["auth_type"] = a.auth_type
            if a.auth_type == "user-pass":
                if not a.username:
                    raise ValueError("webhook user-pass needs --username")
                e["username"] = a.username
                e["password_var"] = f"{s}_password"
            elif a.auth_type == "bearer-token":
                e["auth_token_var"] = f"{s}_token"
            else:
                e["client_cert_data_var"] = f"{s}_client_cert"
                e["private_key_data_var"] = f"{s}_private_key"
    elif a.type in ("slack", "teams"):
        e["url_var"] = f"{s}_url"
        if a.type == "teams" and not a.gateway_source:
            raise ValueError("teams needs --gateway-source (provider 2.0.5 requires gateway_event_source_locations)")
    elif a.type == "service_now":
        if not a.host or a.auth_type not in ("user-pass", "jwt"):
            raise ValueError("service_now needs --host and --auth-type user-pass|jwt")
        e["host"] = a.host
        e["auth_type"] = a.auth_type
        if a.auth_type == "user-pass":
            if not a.admin_name:
                raise ValueError("service_now user-pass needs --admin-name")
            e["admin_name"] = a.admin_name
            e["admin_pwd_var"] = f"{s}_admin_password"
        else:
            if not (a.client_id and a.user_email):
                raise ValueError("service_now jwt needs --client-id and --user-email")
            e["client_id"] = a.client_id
            e["user_email"] = a.user_email
            e["client_secret_var"] = f"{s}_client_secret"
            e["app_private_key_var"] = f"{s}_app_private_key"
    secrets = [v for k, v in e.items() if k.endswith("_var")]
    return e, secrets


HCL_ATTR = {  # model key -> resource argument
    "description": "description", "event_types": "event_types", "runner_type": "runner_type", "every": "every",
    "enable": "enable", "items_event_source_locations": "items_event_source_locations",
    "targets_event_source_locations": "targets_event_source_locations",
    "auth_methods_event_source_locations": "auth_methods_event_source_locations",
    "gateways_event_source_locations": "gateways_event_source_locations",
    "gateway_event_source_locations": "gateway_event_source_locations", "key": "key",
    "email_to": "email_to", "include_error": "include_error", "override_url": "override_url",
    "url": "url", "auth_type": "auth_type", "username": "username", "host": "host", "admin_name": "admin_name",
    "client_id": "client_id", "user_email": "user_email",
}
SECRET_ATTR = {"password_var": "password", "auth_token_var": "auth_token", "client_cert_data_var": "client_cert_data",
               "private_key_data_var": "private_key_data", "url_var": "url", "admin_pwd_var": "admin_pwd",
               "client_secret_var": "client_secret", "app_private_key_var": "app_private_key_base64"}


def _hcl_value(key, v):
    if key == "email_to":
        return json.dumps(",".join(v))                     # provider: comma-separated string
    if key in ("every",):
        return json.dumps(str(v))                          # provider: string (hours)
    if key in ("enable", "include_error"):
        return json.dumps("true" if v else "false")        # provider: "true"/"false" strings
    return json.dumps(v)


def render_hcl(name: str, e: dict) -> str:
    rtype = RESOURCE[e["type"]]
    lines = [f'resource "{rtype}" "{slug(name)}" {{', f"  name = {json.dumps(name)}"]
    for k, v in e.items():
        if k in HCL_ATTR:
            lines.append(f"  {HCL_ATTR[k]} = {_hcl_value(k, v)}")
        elif k in SECRET_ATTR:
            lines.append(f"  {SECRET_ATTR[k]} = var.event_forwarder_secrets[{json.dumps(v)}]")
    lines.append("}")
    width = max(len(ln.split("=")[0]) for ln in lines if " = " in ln)
    out = []
    for ln in lines:
        if " = " in ln and ln.startswith("  "):
            k, v = ln.split(" = ", 1)
            ln = f"{k.ljust(width)}= {v}"
        out.append(ln)
    return "\n".join(out) + "\n"


def render_yaml(name: str, e: dict) -> str:
    return yaml.safe_dump({name: e}, sort_keys=False, width=140)


def insert_into(path: str, name: str, e: dict) -> None:
    """Insert the entry under event_forwarders: keeping the rest of the file (and comments) untouched."""
    text = open(path, encoding="utf-8").read() if os.path.exists(path) else ""
    doc = yaml.safe_load(text) or {}
    if name in (doc.get("event_forwarders") or {}):
        raise ValueError(f"{name} already exists in {path}")
    block = "".join("  " + ln + "\n" for ln in render_yaml(name, e).splitlines())
    lines = text.splitlines(keepends=True)
    idx = next((i for i, ln in enumerate(lines) if re.match(r"^event_forwarders:\s*(#.*)?$", ln)), None)
    if idx is None:
        new = text + ("" if text.endswith("\n") or not text else "\n") + ("\n" if text else "") + "event_forwarders:\n" + block
    else:
        end = idx + 1
        while end < len(lines) and (lines[end].strip() == "" or lines[end].startswith((" ", "#"))):
            end += 1
        while end > idx + 1 and (lines[end - 1].strip() == "" or lines[end - 1].startswith("#")):
            end -= 1                                       # blank lines / top-level comments belong to what follows
        new = "".join(lines[:end]) + block + "".join(lines[end:])
    check = yaml.safe_load(new) or {}
    if (check.get("event_forwarders") or {}).get(name) != yaml.safe_load(render_yaml(name, e))[name]:
        raise RuntimeError("insertion check failed - file left unchanged")
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(new)


def main(argv: list[str] | None = None) -> None:
    a = build_parser().parse_args(argv)
    try:
        e, secrets = build_entry(a)
        if a.format == "hcl":
            if a.write:
                raise ValueError("--write works with --format yaml")
            print(render_hcl(a.name, e), end="")
            if any(k.endswith("_var") for k in e):
                print("\n# needs: variable \"event_forwarder_secrets\" { type = map(string), sensitive = true }"
                      " (already declared in terraform/main.tf)", file=sys.stderr)
            address = f"{RESOURCE[a.type]}.{slug(a.name)}"
        elif a.write:
            insert_into(a.write, a.name, e)
            print(f"added {a.name} to {a.write}")
            address = f'{RESOURCE[a.type]}.this["{a.name}"]'
        else:
            print("# add under event_forwarders: in terraform/model/governance.yaml")
            print("".join("  " + ln + "\n" for ln in render_yaml(a.name, e).splitlines()), end="")
            address = f'{RESOURCE[a.type]}.this["{a.name}"]'
        if a.import_existing:
            print(f"\n# imports.tf - the forwarder exists already; Terraform adopts it on the next apply\n"
                  f"import {{\n  to = {address}\n  id = {json.dumps(a.name)}\n}}")
        if secrets:
            print("\n# provide these keys in TF_VAR_event_forwarder_secrets (CI secret, JSON map):", file=sys.stderr)
            for s in secrets:
                print(f"#   {s}", file=sys.stderr)
    except (ValueError, RuntimeError) as err:
        print(f"error: {err}", file=sys.stderr)
        sys.exit(2)


if __name__ == "__main__":
    main()
