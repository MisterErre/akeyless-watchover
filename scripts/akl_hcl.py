#!/usr/bin/env python3
"""Translate Akeyless API JSON into complete Terraform resources, laid out like the exported JSON.

Used by `watchover export --hcl`. Every JSON file under raw/ that holds an object Terraform can manage
becomes a .tf file at the same relative path under hcl/:

  raw/roles/<name>.json        -> hcl/roles/<name>.tf           (module "roles": role + its associations)
  raw/auth_methods/<name>.json -> hcl/auth_methods/<name>.tf
  raw/targets/<name>.json      -> hcl/targets/<name>.tf ...     (every directory is a module)
  raw/custom_fields.json       -> hcl/custom_fields.tf ...      (files at the root stay at the root)

A directory of .tf files is a Terraform module, so hcl/ is a root module that calls one module per
directory (main.tf) and holds every import block (imports.tf), the providers and the variables.

Attributes come from the provider's own read code: scripts/data/provider-<version>.json maps each API
JSON field to the attribute the provider sets from it (see scripts/tools/extract_provider_map.py), with
the provider's schema for types. Per resource:
  - mapped fields become attributes, converted to the schema type;
  - secrets are never written: they become var.secrets["<object>:<attribute>"];
  - required attributes the API does not return become var.inputs["<object>:<attribute>"];
  - every JSON field that was not translated is kept as a comment, so no data is lost silently.
"""
from __future__ import annotations

import json
import os
import re

HERE = os.path.dirname(os.path.abspath(__file__))
PROVIDER_VERSION = "2.0.5"
DATA = json.load(open(os.path.join(HERE, "data", f"provider-{PROVIDER_VERSION}.json"), encoding="utf-8"))["resources"]

SECRET_RE = re.compile(r"(secret|password|passwd|token|private|api_?key$|(^|_)access_key$|key_data$|client_key"
                       r"|credential|creds|_pfx|tls_certificate|encryption_key)")
NOT_SECRET = {"key", "access_key_id", "token_ttl", "secret_name", "max_token_ttl"}
# settings whose names contain a secret-like word but hold policy values (password_length, create_private_crl...)
NOT_SECRET_RE = re.compile(r"(_length|_ttl|_ttl_enable|_expiration|_enable|_enabled|_flag|_days)$"
                           r"|^(enable|hide|use|create|allow|public)_")


# ------------------------------------------------------------------------------------------- values
def _hcl_str(s: str) -> str:
    return json.dumps(s).replace("${", "$${").replace("%{", "%%{")


def lit(v) -> str:
    """A Python value as an HCL literal."""
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, (int, float)):
        return str(int(v)) if float(v).is_integer() else str(v)
    if isinstance(v, str):
        return _hcl_str(v)
    if isinstance(v, list):
        return "[" + ", ".join(lit(x) for x in v) + "]"
    if isinstance(v, dict):
        return "{ " + ", ".join(f"{_hcl_str(str(k))} = {lit(x)}" for k, x in v.items()) + " }" if v else "{}"
    return _hcl_str(str(v))


def get_path(obj, path: list[str]):
    """Follow a JSON path; lists are entered at their first element; a missing first segment is skipped
    (list endpoints return the inner object, e.g. `policy.path` -> `path`)."""
    def walk(o, p):
        for seg in p:
            if isinstance(o, list):
                o = o[0] if o else None
            if not isinstance(o, dict) or seg not in o:
                return None
            o = o[seg]
        return o
    v = walk(obj, path)
    if v is None and len(path) > 1:
        v = walk(obj, path[1:])
    return v


def transform(v, tr: str):
    if v is None:
        return None
    if tr == "split_comma" and isinstance(v, str):
        return [x.strip() for x in v.split(",") if x.strip()]
    if tr == "join_comma" and isinstance(v, list):
        return ",".join(str(x) for x in v)
    if tr == "not" and isinstance(v, bool):
        return not v
    if tr == "tostring" and isinstance(v, bool):
        return "true" if v else "false"
    if tr == "not_tostring" and isinstance(v, bool):
        return "false" if v else "true"
    return v


def coerce(v, typ):
    """Convert to the schema type; None when it cannot be represented."""
    if v is None:
        return None
    if typ == "string":
        if isinstance(v, bool):
            return "true" if v else "false"
        if isinstance(v, (int, float)):
            return str(int(v)) if float(v).is_integer() else str(v)
        if isinstance(v, list) and all(not isinstance(x, (dict, list)) for x in v):
            return ",".join(str(x) for x in v)
        if isinstance(v, dict):
            return None
        return str(v)
    if typ == "number":
        try:
            return int(v) if float(v).is_integer() else float(v)
        except (TypeError, ValueError):
            return None
    if typ == "bool":
        if isinstance(v, bool):
            return v
        if isinstance(v, str) and v.lower() in ("true", "false"):
            return v.lower() == "true"
        return None
    if isinstance(typ, list) and typ[0] in ("list", "set"):
        if isinstance(v, str):
            v = [x.strip() for x in v.split(",") if x.strip()]
        if not isinstance(v, list):
            return None
        out = [coerce(x, typ[1]) for x in v]
        return None if any(x is None for x in out) else out
    if isinstance(typ, list) and typ[0] == "map":
        if not isinstance(v, dict):
            return None
        return {str(k): (",".join(map(str, x)) if isinstance(x, list) else coerce(x, typ[1])) for k, x in v.items()}
    return None


def is_empty(v) -> bool:
    return v is None or v == "" or v == [] or v == {}


def is_secret(attr: str, spec) -> bool:
    if spec[2]:                                       # sensitive in the provider schema
        return True
    return (attr not in NOT_SECRET and spec[0] == "string" and bool(SECRET_RE.search(attr))
            and not NOT_SECRET_RE.search(attr))


def placeholder(var: str, key: str, typ) -> str:
    ref = f'var.{var}[{_hcl_str(key)}]'
    if typ == "number":
        return f"tonumber({ref})"
    if typ == "bool":
        return f"tobool({ref})"
    if isinstance(typ, list) and typ[0] in ("list", "set"):
        return f'split(",", {ref})'
    if isinstance(typ, list) and typ[0] == "map":
        return f"jsondecode({ref})"
    return ref


def example_value(typ) -> str:
    return {"number": "0", "bool": "false"}.get(typ, "[]" if isinstance(typ, list) and typ[0] == "map" else "")


def tfvars_map(name: str, entries: dict[str, str]) -> str:
    """`name = { "k" = v }` aligned like terraform fmt (values are HCL literals)."""
    w = max((len(lit(k)) for k in entries), default=0)
    return f"{name} = {{\n" + "".join(f"  {lit(k).ljust(w)} = {v}\n" for k, v in sorted(entries.items())) + "}\n"


def leaves(obj, prefix=()):
    if isinstance(obj, dict):
        for k, v in obj.items():
            yield from leaves(v, prefix + (k,))
    elif isinstance(obj, list) and obj and all(isinstance(x, dict) for x in obj):
        for i, x in enumerate(obj):
            yield from leaves(x, prefix + (f"[{i}]",))
    else:
        yield prefix, obj


# ------------------------------------------------------------------------------------------- resources
class Resource:
    def __init__(self, rtype: str, label: str, name: str):
        self.rtype, self.label, self.name = rtype, label, name
        self.attrs: dict[str, str] = {}               # attribute -> HCL expression
        self.blocks: list[tuple[str, dict[str, str]]] = []
        self.comments: list[str] = []
        self.secrets: dict[str, object] = {}          # var.secrets key -> type
        self.inputs: dict[str, object] = {}           # var.inputs key  -> type
        self.used: set = set()                        # JSON paths consumed

    @property
    def spec(self):
        return DATA.get(self.rtype, {"attrs": {}, "map": [], "blocks": {}})

    def set(self, attr: str, value, *, expr: bool = False):
        a = self.spec["attrs"].get(attr)
        if a is None or a[1] == "C":
            return
        if expr:
            self.attrs[attr] = value
            return
        v = coerce(value, a[0])
        if is_empty(v):
            return
        if is_secret(attr, a):
            key = f"{self.name}:{attr}"
            self.secrets[key] = a[0]
            self.attrs[attr] = placeholder("secrets", key, a[0])
        else:
            self.attrs[attr] = lit(v)

    def apply_map(self, obj: dict):
        for path, attr, tr in self.spec["map"]:
            v = transform(get_path(obj, path), tr)
            a = self.spec["attrs"].get(attr)
            if v is None or a is None or a[1] == "C":
                continue
            self.used.add(tuple(path))
            if len(path) > 1:
                self.used.add(tuple(path[1:]))
            if attr in self.attrs:
                continue
            if is_secret(attr, a) and (v == "<redacted>" or v not in (None, "", [])):
                key = f"{self.name}:{attr}"
                self.secrets[key] = a[0]
                self.attrs[attr] = placeholder("secrets", key, a[0])
                continue
            self.set(attr, v)

    def match_by_name(self, obj: dict):
        """Fields the provider's read code does not map but whose name IS an attribute (e.g. delete_protection):
        set them, and say so - these are not confirmed by the read code."""
        matched = []
        for path, v in leaves(obj):
            plain = tuple(p for p in path if not p.startswith("["))
            attr = plain[-1] if plain else ""
            spec = self.spec["attrs"].get(attr)
            if (not spec or spec[1] == "C" or attr in self.attrs or attr in ("name", "id") or len(plain) > 3
                    or is_secret(attr, spec) or any(u and plain[:len(u)] == u for u in self.used) or is_empty(v)):
                continue
            before = len(self.attrs)
            self.set(attr, v)
            if len(self.attrs) > before:
                self.used.add(plain)
                matched.append(attr)
        if matched:
            self.comments.append("matched by field name, not by the provider read code (VERIFY): " + ", ".join(matched))

    def fill_required(self):
        for attr, (typ, flag, _s) in self.spec["attrs"].items():
            if flag == "R" and attr not in self.attrs:
                key = f"{self.name}:{attr}"
                self.inputs[key] = typ
                self.attrs[attr] = placeholder("inputs", key, typ)
                self.comments.append(f"{attr}: not returned by the API - set var.inputs[{_hcl_str(key)}]")

    def keep_unmapped(self, obj: dict, skip=()):
        for path, v in leaves(obj):
            plain = tuple(p for p in path if not p.startswith("["))       # list indexes do not count
            if is_empty(v) or any(u and plain[:len(u)] == u for u in self.used) or path[:1] in skip:
                continue
            text = json.dumps(v, default=str)
            if SECRET_RE.search(path[-1]) and path[-1] not in NOT_SECRET and isinstance(v, str):
                text = '"<redacted>"'
            if len(text) > 120:
                text = text[:117] + "..."
            self.comments.append(f"raw {'.'.join(path).replace('.[', '[')} = {text}")

    def render(self) -> str:
        out = [f"# {c}" for c in self.comments]
        out.append(f'resource "{self.rtype}" "{self.label}" {{')
        out += _aligned(self.attrs, "  ")
        for bname, battrs in self.blocks:
            out += ["", f"  {bname} {{"] + _aligned(battrs, "    ") + ["  }"]
        out.append("}")
        return "\n".join(out) + "\n"


def _aligned(attrs: dict[str, str], ind: str) -> list[str]:
    order = sorted(attrs, key=lambda k: (k != "name", k))
    w = max((len(k) for k in order), default=0)
    return [f"{ind}{k.ljust(w)} = {attrs[k]}" for k in order]


def generic(rtype: str, label: str, name: str, obj: dict) -> Resource:
    r = Resource(rtype, label, name)
    if "name" in r.spec["attrs"] and name:
        r.set("name", name)
    r.apply_map(obj)
    r.match_by_name(obj)
    return r


def _tf_name(s: str, used: set) -> str:
    base = re.sub(r"[^A-Za-z0-9_]", "_", s.strip("/")).strip("_").lower() or "this"
    base = base if base[0].isalpha() else "r_" + base
    cand, i = base, 2
    while cand in used:
        cand, i = f"{base}_{i}", i + 1
    used.add(cand)
    return cand


# ------------------------------------------------------------------------------------------- tree
class Tree:
    """hcl/ as modules: {module path tuple: {file stem: [Resource]}}."""

    def __init__(self):
        self.files: dict[tuple, dict[str, list[Resource]]] = {(): {}}
        self.labels: dict[tuple, dict[str, set]] = {}
        self.imports: list[tuple[str, str]] = []
        self.gateway_modules: set = set()

    def label(self, mod: tuple, rtype: str, hint: str) -> str:
        return _tf_name(hint, self.labels.setdefault(mod, {}).setdefault(rtype, set()))

    def add(self, mod: tuple, stem: str, res: Resource, import_id: str | None):
        for i in range(len(mod) + 1):
            self.files.setdefault(mod[:i], {})
        self.files[mod].setdefault(stem, []).append(res)
        if import_id is not None:
            addr = "".join(f"module.{m}." for m in mod) + f"{res.rtype}.{res.label}"
            self.imports.append((addr, import_id))

    def secrets(self):
        out = {}
        for mod in self.files.values():
            for rs in mod.values():
                for r in rs:
                    out.update(r.secrets)
        return out

    def inputs(self):
        out = {}
        for mod in self.files.values():
            for rs in mod.values():
                for r in rs:
                    out.update(r.inputs)
        return out

    def write(self, out_dir: str, header: str) -> list[str]:
        written = []
        vars_tf = ('variable "secrets" {\n  description = "Secret values, key \\"<object>:<attribute>\\" '
                   '(see terraform.tfvars.example)."\n  type        = map(string)\n  sensitive   = true\n'
                   '  default     = {}\n}\n\nvariable "inputs" {\n  description = "Required values the API does '
                   'not return, key \\"<object>:<attribute>\\"."\n  type        = map(string)\n  default     = {}\n}\n')
        req = ('terraform {\n  required_providers {\n    akeyless = {\n      source  = "akeyless-community/akeyless"\n'
               f'      version = "~> {PROVIDER_VERSION.rsplit(".", 1)[0]}"\n    }}\n  }}\n}}\n')
        for mod, files in sorted(self.files.items()):
            d = os.path.join(out_dir, *mod)
            os.makedirs(d, exist_ok=True)
            children = sorted({m[len(mod)] for m in self.files if len(m) > len(mod) and m[:len(mod)] == mod})
            if mod:
                with open(os.path.join(d, "versions.tf"), "w") as fh:
                    fh.write(header + req + "\n" + vars_tf)
                written.append(os.path.join(*mod, "versions.tf"))
            if children:
                with open(os.path.join(d, "main.tf"), "w") as fh:
                    fh.write(header + "\n".join(
                        (f'module "{c}" {{\n  source = "./{c}"\n  providers = {{\n    akeyless = akeyless.gateway\n  }}\n'
                         if not mod and (c,) in self.gateway_modules else f'module "{c}" {{\n  source  = "./{c}"\n')
                        + "  secrets = var.secrets\n  inputs  = var.inputs\n}\n" for c in children))
                written.append(os.path.join(*mod, "main.tf") if mod else "main.tf")
            for stem, resources in sorted(files.items()):
                with open(os.path.join(d, stem + ".tf"), "w") as fh:
                    fh.write(header + "\n".join(r.render() for r in resources))
                written.append(os.path.join(*mod, stem + ".tf") if mod else stem + ".tf")
        return written
