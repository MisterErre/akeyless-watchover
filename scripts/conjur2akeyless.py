#!/usr/bin/env python3
"""Translate CyberArk Conjur policy (RBAC) into the akeyless-watchover YAML model.

Akeyless "Automatic Migration" (Gateway, type conjur) copies *secret values* only.
Conjur's authorization model (policies, hosts, layers, groups, permits, grants) has
to be rebuilt as Akeyless roles - this script does the mechanical part:

  Conjur                               Akeyless model
  -----------------------------------  ------------------------------------------------
  !variable  <policy>/<id>             item  <prefix>/<policy>/<id>
  !permit  privileges on a variable    rule on that item path:
      execute (fetch value)  -> read       read   (+ list implied)
      read    (see metadata) -> list       list
      update  (set value)    -> update     update
  role with permits (layer/group/      one Akeyless role  <role_prefix>conjur/<kind>-<id>
      host/user/policy)
  !grant  role: A, member: B           no role nesting in Akeyless -> B is bound to A's
                                       Akeyless role too (flattened, transitive)
  host / user identities               bindings report: which Akeyless roles each Conjur
                                       identity needs; YOU map it to an auth method +
                                       sub-claims (e.g. authn-jwt -> OAuth2/JWT auth method)

Supported policy statements: !policy (id, body), !variable, !host, !layer, !group, !user,
!webservice, !permit, !grant, !deny (reported, not translated). Annotations are ignored.

Usage:
  python3 scripts/conjur2akeyless.py policy-root.yml [more.yml ...] \
      --item-prefix /conjur --role-prefix /governance/roles/ --out export/conjur
Writes <out>/roles/conjur.yaml, <out>/bindings.yaml and <out>/REPORT.md.

VERIFY: where the Gateway migration places each Conjur variable (target-location + Conjur
variable id is assumed here) - compare with the migrated item names before applying.
"""
from __future__ import annotations

import argparse
import os
import re
import sys
from collections import defaultdict

import yaml

KINDS = ["policy", "variable", "host", "layer", "group", "user", "webservice"]
PRIV_MAP = {"execute": "read", "read": "list", "update": "update"}


class Ref:
    def __init__(self, kind: str, value):
        self.kind, self.value = kind, value

    def __repr__(self):
        return f"!{self.kind} {self.value!r}"


class Stmt(Ref):
    pass


def _loader():
    class L(yaml.SafeLoader):
        pass

    def make(kind, cls):
        def ctor(loader, node):
            if isinstance(node, yaml.ScalarNode):
                return cls(kind, loader.construct_scalar(node))
            if isinstance(node, yaml.SequenceNode):
                return cls(kind, loader.construct_sequence(node, deep=True))
            return cls(kind, loader.construct_mapping(node, deep=True))
        return ctor

    for k in KINDS:
        L.add_constructor(f"!{k}", make(k, Stmt))
    for k in ["permit", "grant", "deny", "delete", "revoke"]:
        L.add_constructor(f"!{k}", make(k, Stmt))
    return L


def join_id(ns: str, ident: str) -> str:
    ident = str(ident)
    if ident.startswith("/"):
        return ident.strip("/")
    return "/".join(p for p in [ns, ident] if p)


def stmt_id(s: Stmt) -> str:
    v = s.value
    if isinstance(v, dict):
        return str(v.get("id", ""))
    return "" if v is None else str(v)


def as_refs(v) -> list[Stmt]:
    if v is None:
        return []
    if isinstance(v, list):
        out = []
        for x in v:
            out += as_refs(x)
        return out
    return [v]


class Policy:
    def __init__(self):
        self.variables: set[str] = set()
        self.identities: dict[str, str] = {}             # full id -> kind (host/user/layer/group/policy)
        self.permits: dict[tuple, set] = defaultdict(set)  # (kind, role_id) -> {(variable_id, privilege)}
        self.grants: list[tuple] = []                    # ((kind, role_id), (kind, member_id))
        self.notes: list[str] = []

    def walk(self, statements, ns: str = ""):
        for s in statements or []:
            if isinstance(s, list):          # anchored groups: - &variables [ !variable a, ... ]
                self.walk(s, ns)
                continue
            if not isinstance(s, Stmt):
                self.notes.append(f"- ignored non-statement entry under `{ns or '/'}`: {s!r}")
                continue
            if s.kind == "policy":
                pid = join_id(ns, stmt_id(s))
                self.identities[pid] = "policy"
                self.walk((s.value or {}).get("body") if isinstance(s.value, dict) else [], pid)
            elif s.kind == "variable":
                self.variables.add(join_id(ns, stmt_id(s)))
            elif s.kind in ("host", "layer", "group", "user"):
                self.identities[join_id(ns, stmt_id(s))] = s.kind
            elif s.kind == "webservice":
                self.notes.append(f"- webservice `{join_id(ns, stmt_id(s))}` not translated (no Akeyless equivalent)")
            elif s.kind == "permit":
                v = s.value
                privs = v.get("privileges") or v.get("privilege") or []
                privs = privs if isinstance(privs, list) else [privs]
                for role in as_refs(v.get("role")):
                    for res in as_refs(v.get("resource") or v.get("resources")):
                        rid = join_id(ns, stmt_id(res))
                        if res.kind != "variable":
                            self.notes.append(f"- permit on {res.kind} `{rid}` ignored (only variables carry secrets)")
                            continue
                        for p in privs:
                            if p in PRIV_MAP:
                                self.permits[(role.kind, join_id(ns, stmt_id(role)))].add((rid, p))
                            else:
                                self.notes.append(f"- privilege `{p}` on `{rid}` has no Akeyless mapping")
            elif s.kind == "grant":
                v = s.value
                for role in as_refs(v.get("role")):
                    for mem in as_refs(v.get("member") or v.get("members")):
                        self.grants.append(((role.kind, join_id(ns, stmt_id(role))), (mem.kind, join_id(ns, stmt_id(mem)))))
            else:
                self.notes.append(f"- `!{s.kind}` statement under `{ns or '/'}` not translated - review manually")


def slug(s: str) -> str:
    return re.sub(r"[^A-Za-z0-9_-]+", "-", s).strip("-").lower()


def translate(pol: Policy, item_prefix: str, role_prefix: str):
    item_prefix = "/" + item_prefix.strip("/") if item_prefix.strip("/") else ""
    roles, akl_name = {}, {}
    for (kind, rid), perms in sorted(pol.permits.items()):
        name = f"{role_prefix.rstrip('/')}/conjur/{kind}-{slug(rid)}"
        akl_name[(kind, rid)] = name
        by_path = defaultdict(set)
        for var, p in perms:
            by_path[f"{item_prefix}/{var}"].add(PRIV_MAP[p])
        roles[name] = {
            "description": f"Translated from Conjur {kind} '{rid}'",
            "allow_external_auth_methods": True,
            "rules": [{"path": path, "capabilities": sorted(caps | ({"list"} if caps - {"list"} else set()))}
                      for path, caps in sorted(by_path.items())],
        }
    # transitive membership: member -> set of roles it belongs to
    parents = defaultdict(set)
    for role, member in pol.grants:
        parents[member].add(role)

    def closure(node, seen=None):
        seen = seen or set()
        for p in parents.get(node, ()):
            if p not in seen:
                seen.add(p)
                closure(p, seen)
        return seen

    bindings = {}
    for ident, kind in sorted(pol.identities.items()):
        if kind not in ("host", "user"):
            continue
        reachable = {(kind, ident)} | closure((kind, ident))
        names = sorted(akl_name[r] for r in reachable if r in akl_name)
        if names:
            bindings[f"{kind}:{ident}"] = {
                "akeyless_roles": names,
                "auth_method": "TODO (e.g. /governance/auth/<idp-or-platform>)",
                "sub_claims": "TODO (claims identifying this workload/user)",
            }
    return roles, bindings


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("policy", nargs="+", help="Conjur policy YAML files (loaded at the root namespace in the given order)")
    ap.add_argument("--item-prefix", default="/conjur", help="Akeyless folder the Gateway migration imports into")
    ap.add_argument("--role-prefix", default="/governance/roles/", help="prefix of the generated Akeyless role names")
    ap.add_argument("--out", required=True, help="output directory (roles/conjur.yaml, bindings.yaml, REPORT.md)")
    return ap


def main(argv: list[str] | None = None) -> None:
    try:
        _main(argv)
    except (yaml.YAMLError, OSError) as e:
        print(f"error: {e}", file=sys.stderr)
        sys.exit(2)


def _main(argv: list[str] | None = None) -> None:
    a = build_parser().parse_args(argv)
    pol = Policy()
    for f in a.policy:
        with open(f, encoding="utf-8") as fh:
            pol.walk(yaml.load(fh, Loader=_loader()) or [])
    roles, bindings = translate(pol, a.item_prefix, a.role_prefix)
    os.makedirs(os.path.join(a.out, "roles"), exist_ok=True)
    with open(os.path.join(a.out, "roles", "conjur.yaml"), "w") as fh:
        yaml.safe_dump({"roles": roles}, fh, sort_keys=True, width=140)
    with open(os.path.join(a.out, "bindings.yaml"), "w") as fh:
        yaml.safe_dump({"bindings": bindings}, fh, sort_keys=True, width=140)
    unused = sorted(v for v in pol.variables if not any(v == var for perms in pol.permits.values() for var, _ in perms))
    with open(os.path.join(a.out, "REPORT.md"), "w") as fh:
        fh.write(f"# Conjur translation report\n\nvariables: {len(pol.variables)}, Akeyless roles: {len(roles)}, "
                 f"identities with access: {len(bindings)}\n\n## Needs review\n\n"
                 + ("\n".join(pol.notes) or "Nothing.") + "\n\n## Variables nobody is permitted to use\n\n"
                 + ("\n".join(f"- {v}" for v in unused) or "None.") + "\n\n## Next steps\n\n"
                 "1. Fill auth_method + sub_claims for every entry in bindings.yaml and add them as `associations` to the roles.\n"
                 "2. Move roles/conjur.yaml into terraform/model/roles/ and run the tests/plan.\n"
                 "3. Run the Gateway Conjur migration (akeyless_gateway_migration_conjur) into the same --item-prefix.\n")
    print(f"{len(roles)} roles, {len(bindings)} identities, {len(pol.notes)} note(s) -> {a.out}")


if __name__ == "__main__":
    main()
