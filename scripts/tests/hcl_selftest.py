#!/usr/bin/env python3
"""Self-test of the HCL translation for EVERY resource in scripts/data/provider-<version>.json.

For each resource with a read mapping, builds an API JSON object that sets every mapped field (with a value of
the type the attribute expects, reversed through the transform), translates it with akl_hcl and writes all
resources into one Terraform root module. export_roundtrip.sh then runs `validate` and a mocked `plan` on it,
which proves that every generated attribute has the right name and type.

Usage: hcl_selftest.py OUT_DIR
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
import akl_hcl as H  # noqa: E402


def sample(typ, tr):
    if tr in ("not", ""):
        base = {"number": 7, "bool": True}.get(typ if isinstance(typ, str) else "", None)
    else:
        base = None
    if tr in ("tostring", "not_tostring", "not"):
        return True
    if tr == "split_comma":
        return "a,b"
    if tr == "join_comma":
        return ["a", "b"]
    if base is not None:
        return base
    if isinstance(typ, list) and typ[0] in ("list", "set"):
        return [7] if typ[1] == "number" else ["a"]
    if isinstance(typ, list) and typ[0] == "map":
        return {"k": "v"}
    return "x"


def _input(typ):
    if isinstance(typ, list):
        return "{}" if typ[0] == "map" else "x"
    return {"number": "1", "bool": "true"}.get(typ, "x")


def put(obj, path, value):
    for seg in path[:-1]:
        obj = obj.setdefault(seg, {})
    obj[path[-1]] = value


def main(out):
    os.makedirs(out, exist_ok=True)
    blocks, n, secrets, inputs = [], 0, {}, {}
    for rtype, spec in sorted(H.DATA.items()):
        if not spec["map"]:
            continue
        obj: dict = {}
        for path, attr, tr in spec["map"]:
            a = spec["attrs"].get(attr)
            if a and a[1] != "C":
                put(obj, path, sample(a[0], tr))
        r = H.generic(rtype, f"t{n}", f"/selftest/{rtype}", obj)
        r.fill_required()
        secrets.update(r.secrets)
        inputs.update(r.inputs)
        blocks.append(r.render())
        n += 1
    with open(os.path.join(out, "main.tf"), "w") as fh:
        fh.write('terraform {\n  required_providers {\n    akeyless = {\n      source  = "akeyless-community/akeyless"\n'
                 f'      version = "{H.PROVIDER_VERSION}"\n    }}\n  }}\n}}\n\n'
                 'variable "secrets" {\n  type      = map(string)\n  sensitive = true\n  default   = {}\n}\n\n'
                 'variable "inputs" {\n  type    = map(string)\n  default = {}\n}\n\n' + "\n".join(blocks))
    with open(os.path.join(out, "terraform.tfvars"), "w") as fh:
        fh.write(H.tfvars_map("secrets", {k: '"x"' for k in secrets}) + "\n"
                 + H.tfvars_map("inputs", {k: H.lit(_input(v)) for k, v in inputs.items()}))
    os.makedirs(os.path.join(out, "tests"), exist_ok=True)
    with open(os.path.join(out, "tests", "plan.tftest.hcl"), "w") as fh:
        fh.write('mock_provider "akeyless" {}\n\nrun "every_translated_resource_plans" {\n  command = plan\n}\n')
    print(f"{n} resource types translated -> {out}/main.tf")


if __name__ == "__main__":
    main(sys.argv[1])
