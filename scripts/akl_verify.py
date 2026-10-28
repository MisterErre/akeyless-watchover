#!/usr/bin/env python3
"""Live access verification against Akeyless (after apply).

For every check in the expectations file, runs - as the persona's CLI profile -
    akeyless describe-permissions --path <path> --type <item|am|role|target> --json [--profile P]
which returns the *caller's* own permissions on that path ({"client_permissions": [...]}),
and compares them with the expected set.

Personas need a `profile:` (an `akeyless configure` profile authenticating as that
persona, e.g. a test SSO user in the right IdP group or a test workload identity).
Personas without a profile are skipped (use the Console "Impersonate As" for those).

Usage:
  python3 scripts/akl_verify.py --expectations terraform/model/access_expectations.yaml [--akeyless akeyless]
Exit code 0 = all checked expectations met, 1 = mismatch, 2 = execution error.
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys

from akl_model import load_yaml

CLI_TYPE = {"item": "item", "target": "target", "role": "role", "auth-method": "am", "am": "am"}


def describe(cli: str, path: str, obj_type: str, profile: str, error_means_no_access: bool) -> set[str]:
    cmd = [cli, "describe-permissions", "--path", path, "--type", CLI_TYPE[obj_type], "--json", "--profile", profile]
    res = subprocess.run(cmd, capture_output=True, text=True)
    if res.returncode != 0:
        msg = (res.stderr or res.stdout).strip()
        # How the CLI reports "no access at all" is not documented: by default an error
        # stops the run; with --error-means-no-access it counts as an empty permission set.
        if error_means_no_access:
            return set()
        raise RuntimeError(f"{' '.join(cmd)} failed: {msg}")
    data = json.loads(res.stdout or "{}")
    return {str(c) for c in (data.get("client_permissions") or [])}


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--expectations", required=True, help="access_expectations.yaml (personas need a 'profile')")
    ap.add_argument("--akeyless", default="akeyless", help="path to the akeyless CLI binary")
    ap.add_argument("--error-means-no-access", action="store_true",
                    help="treat a failing describe-permissions call as 'no permissions' (check the CLI behaviour first)")
    return ap


def main(argv: list[str] | None = None) -> None:
    a = build_parser().parse_args(argv)
    exp = load_yaml(a.expectations)
    personas = exp.get("personas") or {}
    failures = skipped = 0
    for chk in exp.get("checks") or []:
        p = personas[chk["persona"]]
        if not p.get("profile"):
            skipped += 1
            continue
        try:
            got = describe(a.akeyless, chk["path"], chk.get("type", "item"), p["profile"], a.error_means_no_access)
        except (RuntimeError, json.JSONDecodeError) as e:
            print(f"ERROR {e}", file=sys.stderr)
            sys.exit(2)
        want = set(chk.get("expect") or [])
        ok = got == want
        failures += 0 if ok else 1
        print(f"{'PASS' if ok else 'FAIL'}  {chk['persona']:<24} {chk['path']:<50} expect={sorted(want)} got={sorted(got)}")
    print(f"\n{failures} mismatch(es), {skipped} check(s) skipped (persona without profile)")
    sys.exit(1 if failures else 0)


if __name__ == "__main__":
    main()
