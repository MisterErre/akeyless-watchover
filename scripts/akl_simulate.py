#!/usr/bin/env python3
"""Offline access check of the YAML model against expected access (no Akeyless calls).

Usage:
  python3 scripts/akl_simulate.py --model terraform/model \
      --expectations terraform/model/access_expectations.yaml [--explain]

Exit code 0 = all expectations met, 1 = mismatch, 2 = usage/model error.
"""
from __future__ import annotations

import argparse
import sys

from akl_model import Model, effective_capabilities, load_yaml


def run(model_dir: str, expectations_file: str, explain: bool = False) -> int:
    model = Model.load(model_dir)
    exp = load_yaml(expectations_file)
    personas = exp.get("personas") or {}
    failures = 0
    for i, chk in enumerate(exp.get("checks") or [], 1):
        p = personas.get(chk["persona"])
        if p is None:
            print(f"[{i}] unknown persona {chk['persona']!r}", file=sys.stderr)
            return 2
        got, why = effective_capabilities(model, p["auth_method"], p.get("claims") or {},
                                          chk["path"], chk.get("type", "item"))
        want = set(chk.get("expect") or [])
        ok = got == want
        failures += 0 if ok else 1
        print(f"{'PASS' if ok else 'FAIL'}  {chk['persona']:<24} {chk.get('type', 'item'):<11} "
              f"{chk['path']:<50} expect={sorted(want)} got={sorted(got)}")
        if explain or not ok:
            for line in why or ["no matching rule"]:
                print(f"        {line}")
    print(f"\n{failures} mismatch(es)")
    return 1 if failures else 0


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--model", required=True, help="model directory (terraform/model)")
    ap.add_argument("--expectations", required=True, help="access_expectations.yaml")
    ap.add_argument("--explain", action="store_true", help="print the matching rules for every check, not only failures")
    return ap


def main(argv: list[str] | None = None) -> None:
    a = build_parser().parse_args(argv)
    try:
        sys.exit(run(a.model, a.expectations, a.explain))
    except (ValueError, KeyError) as e:
        print(f"error: {e}", file=sys.stderr)
        sys.exit(2)


if __name__ == "__main__":
    main()
