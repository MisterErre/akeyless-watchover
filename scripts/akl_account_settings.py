#!/usr/bin/env python3
"""Apply the account settings that Terraform provider 2.0.5 cannot manage.

Reads `account_settings_cli` from model/governance.yaml. Keys are the flag names of
`akeyless update-account-settings` (without the leading --):
  * lists  -> the flag is repeated once per value   (--bound-ips a --bound-ips b)
  * bools  -> --flag=true / --flag=false
  * others -> --flag=value
`update-account-settings` is admin-only and idempotent (same input -> same state).

Usage:
  python3 scripts/akl_account_settings.py --governance terraform/model/governance.yaml [--dry-run] [--profile P]
"""
from __future__ import annotations

import argparse
import os
import shlex
import subprocess
import sys

from akl_model import load_yaml

# Keys the Terraform resource already manages: keep them in `account_settings`, not here,
# so two tools never fight over the same setting.
TF_MANAGED = {
    "company-name", "default-share-link-ttl-minutes", "default-versioning", "dynamic-secret-max-ttl",
    "dynamic-secret-max-ttl-enable", "enable-ai-quorum", "enable-item-sharing", "enable-password-expiration",
    "hide-personal-folder", "hide-static-password", "invalid-characters", "item-locking-enabled",
    "items-deletion-protection", "jwt-ttl-default", "jwt-ttl-max", "jwt-ttl-min", "max-versions",
    "password-expiration-days", "password-expiration-notification-days", "password-length",
    "use-capital-letters", "use-lower-letters", "use-numbers", "use-special-characters",
}

# Flags of updateAccountSettings in the Akeyless API (SDK v5.0.x) not covered by the provider.
KNOWN = {
    "address", "allowed-client-type", "allowed-email-domains", "bound-ips", "city", "country",
    "default-certificate-expiration-notification-days", "default-key-name", "dp-enable-classic-key-protection",
    "enable-ai-insights", "enable-default-certificate-expiration-event", "force-new-versions", "gw-bound-ips",
    "item-type", "lock-allowed-client-type", "lock-bound-ips", "lock-default-key", "lock-gw-bound-ips",
    "lock-max-ttl", "max-rotation-interval", "max-rotation-interval-enable", "phone", "postal-code",
    "usage-event-enable", "usage-event-interval", "usage-event-object-type",
}


def build_args(settings: dict) -> list[str]:
    args: list[str] = []
    for key in sorted(settings):
        if key in TF_MANAGED:
            raise ValueError(f"'{key}' is managed by Terraform (governance.yaml account_settings); remove it here")
        if key not in KNOWN:
            raise ValueError(f"unknown update-account-settings flag '{key}' (check `akeyless update-account-settings -h`)")
        val = settings[key]
        if isinstance(val, list):
            for v in val:
                args.append(f"--{key}={v}")
        elif isinstance(val, bool):
            args.append(f"--{key}={'true' if val else 'false'}")
        else:
            args.append(f"--{key}={val}")
    return args


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--governance", required=True, help="path to model/governance.yaml (reads account_settings_cli)")
    ap.add_argument("--profile", help="akeyless CLI profile of an account admin")
    ap.add_argument("--token", default=None,
                    help="Akeyless token (default: $AKEYLESS_TOKEN, e.g. from 'watchover token')")
    ap.add_argument("--akeyless", default="akeyless", help="path to the akeyless CLI binary")
    ap.add_argument("--dry-run", action="store_true", help="print the update-account-settings command, do not run it")
    return ap


def main(argv: list[str] | None = None) -> None:
    a = build_parser().parse_args(argv)
    a.token = a.token or os.environ.get("AKEYLESS_TOKEN")
    settings = load_yaml(a.governance).get("account_settings_cli") or {}
    if not settings:
        print("no account_settings_cli in model - nothing to do")
        return
    try:
        cmd = [a.akeyless, "update-account-settings", *build_args(settings)]
    except ValueError as e:
        print(f"error: {e}", file=sys.stderr)
        sys.exit(2)
    if a.profile:
        cmd += ["--profile", a.profile]
    print("+ " + " ".join(shlex.quote(c) for c in cmd))  # printed before the token is appended
    if a.token:
        cmd += ["--token", a.token]
    if a.dry_run:
        return
    sys.exit(subprocess.run(cmd).returncode)


if __name__ == "__main__":
    main()
