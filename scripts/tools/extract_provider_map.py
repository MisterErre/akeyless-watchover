#!/usr/bin/env python3
"""Maintainer tool: derive the API-JSON -> Terraform-attribute mapping from the provider's own read code.

For every resource, the provider's Read function calls one Akeyless API operation and copies fields of the
response into attributes (`d.Set("attr", rOut.A.B.C)`). This tool parses those statements, resolves the Go
field chain through the Akeyless Go SDK structs to JSON field names, and writes
scripts/data/provider-<version>.json with, per resource:

  api        the API operation the provider reads with (e.g. AuthMethodGet)
  map        [[json path...], attribute, transform] (transform: "" or "split_comma")
  attrs      attribute schema: {name: [type, R|O|C, sensitive]}   (from `tofu providers schema -json`)
  blocks     nested block schema (attributes of each block)

Usage (needs checkouts of the provider and the Go SDK at the versions the provider pins):
  git clone --depth 1 --branch v2.0.5 https://github.com/akeyless-community/terraform-provider-akeyless.git /tmp/tpa
  git clone --depth 1 --branch v5.0.38 https://github.com/akeylesslabs/akeyless-go.git /tmp/ago
  (cd /tmp/sch && tofu init && tofu providers schema -json > schema.json)   # provider pinned to the same version
  python3 scripts/tools/extract_provider_map.py --provider /tmp/tpa --sdk /tmp/ago --schema /tmp/sch/schema.json \\
      --version 2.0.5 --out scripts/data/provider-2.0.5.json
"""
from __future__ import annotations

import argparse
import glob
import json
import os
import re


def sdk_structs(sdk: str) -> dict:
    out = {}
    for f in glob.glob(os.path.join(sdk, "model_*.go")):
        src = open(f, encoding="utf-8").read()
        for m in re.finditer(r"^type (\w+) struct \{\n(.*?)^\}", src, re.S | re.M):
            fields = {}
            for fm in re.finditer(r"^\s+(\w+)\s+(\S+)\s+`json:\"([^\",]+)", m.group(2), re.M):
                fields[fm.group(1)] = (fm.group(3), fm.group(2))
            out[m.group(1)] = fields
    return out


def sdk_returns(sdk: str) -> dict:
    src = "".join(open(f, encoding="utf-8").read() for f in glob.glob(os.path.join(sdk, "api_*.go")))
    return {m.group(1): m.group(2) for m in re.finditer(
        r"func \(r Api(\w+)Request\) Execute\(\) \(([^,]+), \*http\.Response, error\)", src)}


def base_type(t: str) -> str:
    return re.sub(r"^(\*|\[\]|map\[string\])+", "", t)


def func_body(src: str, name: str) -> str | None:
    m = re.search(rf"^func {name}\(", src, re.M)
    if not m:
        return None
    i = src.index("{\n", m.end())
    depth = 0
    for j in range(i, len(src)):
        depth += {"{": 1, "}": -1}.get(src[j], 0)
        if depth == 0:
            return src[i:j + 1]
    return None


def call_args(text: str, start: int) -> str:
    depth = 0
    for j in range(start, len(text)):
        if text[j] == "(":
            depth += 1
        elif text[j] == ")":
            depth -= 1
            if depth == 0:
                return text[start + 1:j]
    return ""


# resources the exporter translates (keeps the data file small)
KEEP = ("akeyless_role", "akeyless_associate_role_auth_method", "akeyless_auth_method_", "akeyless_folder",
        "akeyless_account_custom_field", "akeyless_account_settings", "akeyless_policy_keys", "akeyless_pki_cert_issuer",
        "akeyless_target_", "akeyless_group", "akeyless_gateway_")

CHAIN = r"\*?(\w+)((?:\.(?:Get)?\w+(?:\(\))?)+)"


def resolve(chain: str, t: str, structs: dict):
    path = []
    for part in [p for p in chain.split(".") if p]:
        part = re.sub(r"^Get(\w+)\(\)$", r"\1", part)
        fields = structs.get(base_type(t))
        if not fields or part not in fields:
            return None
        js, t = fields[part]
        path.append(js)
    return path


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--provider", required=True)
    ap.add_argument("--sdk", required=True)
    ap.add_argument("--schema", required=True)
    ap.add_argument("--version", required=True)
    ap.add_argument("--out", required=True)
    a = ap.parse_args()
    structs, returns = sdk_structs(a.sdk), sdk_returns(a.sdk)
    schema = json.load(open(a.schema))
    rs = list(schema["provider_schemas"].values())[0]["resource_schemas"]
    prov = open(os.path.join(a.provider, "akeyless", "provider.go"), encoding="utf-8").read()
    reg = dict(re.findall(r'"(akeyless_\w+)":\s+(\w+)\(\)', prov))
    srcs = {f: open(f, encoding="utf-8").read() for f in glob.glob(os.path.join(a.provider, "akeyless", "*.go"))}
    allsrc = "\n".join(srcs.values())
    out, stats = {}, {}
    for res, ctor in sorted(reg.items()):
        if res not in rs or not res.startswith(KEEP):
            continue
        blk = rs[res]["block"]
        attrs = {k: [v["type"], "R" if v.get("required") else ("C" if v.get("computed") and not v.get("optional") else "O"),
                     bool(v.get("sensitive"))] for k, v in blk.get("attributes", {}).items()}
        blocks = {k: {"nesting": v["nesting_mode"], "max": v.get("max_items", 0),
                      "attrs": {ak: [av["type"], "R" if av.get("required") else "O", bool(av.get("sensitive"))]
                                for ak, av in v["block"].get("attributes", {}).items()}}
                  for k, v in blk.get("block_types", {}).items()}
        entry = {"api": None, "map": [], "attrs": attrs, "blocks": blocks}
        ctor_body = func_body(allsrc, ctor) or ""
        rm = re.search(r"Read(?:Context)?:\s+(\w+)", ctor_body)
        body = func_body(allsrc, rm.group(1)) if rm else None
        if body:
            calls = {v: returns.get(op) for v, op in re.findall(r"(\w+), \w+, err :?= client\.(\w+)\(ctx\)", body)}
            api = re.findall(r"\w+, \w+, err :?= client\.(\w+)\(ctx\)", body)
            if not api:   # the read API is called in a helper of the same resource (e.g. gateway singletons)
                fsrc = next(v for f, v in srcs.items() if re.search(rf"^func {rm.group(1)}\(", v, re.M))
                reads = re.findall(r"(\w+), \w+, err :?= client\.((?:Get|Describe|List|Gateway(?:Get|List))\w*)\(ctx\)", fsrc)
                calls = {v: returns.get(op) for v, op in reads}
                api = [op for _v, op in reads]
                body = fsrc
            entry["api"] = api[0] if api else None
            aliases = {g[0]: g[1] for g in re.findall(rf"^\s*(\w+) :?= ({CHAIN})\s*$", body, re.M) if g[0] not in calls}
            aliases.update({g[0]: g[1] for g in re.findall(rf"for _, (\w+) := range ({CHAIN})\s*\{{", body)})
            for m in re.finditer(r'd\.Set\("(\w+)",', body):
                attr = m.group(1)
                expr = call_args(body, body.index("(", m.start()))
                expr = expr.split(",", 1)[1].strip() if "," in expr else ""
                transform = ""
                for pat, tr in ((r'strings\.Split\((.*),\s*","\)$', "split_comma"),
                                (r'strings\.Join\((.*),\s*","\)$', "join_comma"),
                                (r'strconv\.FormatBool\(!(.*)\)$', "not_tostring"),
                                (r'strconv\.FormatBool\((.*)\)$', "tostring"),
                                (r'boolToStr\(!(.*)\)$', "not_tostring"), (r'boolToStr\((.*)\)$', "tostring"),
                                (r'common\.Base64Encode\((.*)\)$', "base64"),
                                (r'int\((.*)\)$', ""), (r'int64\((.*)\)$', ""), (r'!(.*)$', "not")):
                    sm = re.match(pat, expr)
                    if sm:
                        expr, transform = sm.group(1).strip(), tr
                        break
                for _ in range(5):                       # resolve local aliases: pki := certDetails.Pki...
                    cm = re.fullmatch(CHAIN, expr) or re.fullmatch(r"\*?(\w+)()", expr)
                    if not cm or cm.group(1) in calls or cm.group(1) not in aliases:
                        break
                    expr = aliases[cm.group(1)].lstrip("*") + cm.group(2)
                cm = re.fullmatch(CHAIN, expr)
                if not cm or cm.group(1) not in calls or not calls[cm.group(1)]:
                    continue
                path = resolve(cm.group(2), calls[cm.group(1)], structs)
                if path and attr in attrs and not any(x[1] == attr for x in entry["map"]):
                    entry["map"].append([path, attr, transform])
        out[res] = entry
        stats[res] = len(entry["map"])
    os.makedirs(os.path.dirname(a.out), exist_ok=True)
    with open(a.out, "w") as fh:          # one resource per line: readable diffs when the provider is upgraded
        fh.write('{"provider": "akeyless-community/akeyless", "version": %s, "resources": {\n' % json.dumps(a.version))
        fh.write(",\n".join(f"{json.dumps(k)}: {json.dumps(out[k], sort_keys=True, separators=(',', ':'))}"
                             for k in sorted(out)))
        fh.write("\n}}\n")
    print(f"{len(out)} resources, {sum(1 for v in stats.values() if v)} with read mappings, "
          f"{sum(stats.values())} mapped attributes -> {a.out}")


if __name__ == "__main__":
    main()
