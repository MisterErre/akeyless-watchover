"""Shared helpers: load the YAML governance model and evaluate Akeyless RBAC semantics.

The evaluation implements the *documented* Akeyless behaviour (docs.akeyless.io/docs/rbac,
/docs/sub-claims). It is a fast offline approximation for pull-request checks; the
authoritative answer is always the platform itself (see akl_verify.py).

Documented rules implemented here:
  * '*' matches any characters (also across '/'), used at the end or as a prefix ('/a/devops-*').
  * '+' matches any characters inside exactly one path segment.
  * Every capability implies 'list'.
  * 'deny' overrides all other permissions on the matched path.
  * Sub-claims: comma-separated values within a key = OR, different keys = AND,
    values support '*' and '?' globs, case-sensitive unless case_sensitive is false.
  * Rule paths may be templated with {{claim}} (expanded once per claim value).
Assumptions (not stated by the docs, verify live): '/a/*' does not match '/a' itself;
explicit 'AND'/'OR' operators inside a sub-claim value (Gateway >= 4.19) are evaluated
left to right.
"""
from __future__ import annotations

import fnmatch
import glob
import os
import re
from dataclasses import dataclass, field

import yaml

CRUD = {"read", "list", "create", "update", "delete"}
TYPE_TO_RULE = {"item": "item-rule", "target": "target-rule", "role": "role-rule",
                "auth-method": "auth-method-rule", "am": "auth-method-rule"}


def load_yaml(path: str) -> dict:
    if not os.path.exists(path):
        return {}
    with open(path, encoding="utf-8") as fh:
        return yaml.safe_load(fh) or {}


@dataclass
class Model:
    roles: dict = field(default_factory=dict)
    auth_methods: dict = field(default_factory=dict)

    @classmethod
    def load(cls, model_dir: str) -> "Model":
        roles: dict = {}
        for f in sorted(glob.glob(os.path.join(model_dir, "roles", "*.yaml"))):
            doc = load_yaml(f).get("roles") or {}
            dup = set(doc) & set(roles)
            if dup:
                raise ValueError(f"duplicate role(s) {sorted(dup)} in {f}")
            roles.update(doc)
        ams = load_yaml(os.path.join(model_dir, "auth_methods.yaml")).get("auth_methods") or {}
        return cls(roles=roles, auth_methods=ams)


def _norm(p: str) -> str:
    return "/" + p.strip().lstrip("/")


def path_pattern_to_regex(pattern: str) -> re.Pattern:
    out = []
    for ch in _norm(pattern):
        if ch == "*":
            out.append(".*")
        elif ch == "+":
            out.append("[^/]+")
        else:
            out.append(re.escape(ch))
    return re.compile("^" + "".join(out) + "$")


def path_matches(pattern: str, path: str) -> bool:
    return bool(path_pattern_to_regex(pattern).match(_norm(path)))


def _as_list(v) -> list[str]:
    if v is None:
        return []
    if isinstance(v, (list, tuple)):
        return [str(x) for x in v]
    return [s.strip() for s in str(v).split(",") if s.strip()]


def _glob(pattern: str, value: str, case_sensitive: bool) -> bool:
    if not case_sensitive:
        pattern, value = pattern.lower(), value.lower()
    return fnmatch.fnmatchcase(value, pattern)


def _value_expr_matches(expr: str, values: list[str], cs: bool) -> bool:
    """Evaluate one sub-claim expression against the caller's values for that key."""
    tokens = re.split(r"\s+(AND|OR)\s+", expr.strip())
    result = any(_glob(tokens[0], v, cs) for v in values)
    i = 1
    while i < len(tokens):
        op, operand = tokens[i], tokens[i + 1]
        hit = any(_glob(operand, v, cs) for v in values)
        result = (result and hit) if op == "AND" else (result or hit)
        i += 2
    return result


def sub_claims_match(required: dict, claims: dict, case_sensitive: bool = True) -> bool:
    for key, expected in (required or {}).items():
        caller_values = None
        for ck, cv in (claims or {}).items():
            if ck == key or (not case_sensitive and ck.lower() == str(key).lower()):
                caller_values = _as_list(cv)
        if not caller_values:
            return False
        exprs = [expected] if isinstance(expected, str) and re.search(r"\s(AND|OR)\s", expected) else _as_list(expected)
        if not any(_value_expr_matches(e, caller_values, case_sensitive) for e in exprs):
            return False
    return True


def expand_templates(pattern: str, claims: dict) -> list[str]:
    keys = re.findall(r"\{\{\s*([^}]+?)\s*\}\}", pattern)
    if not keys:
        return [pattern]
    results = [pattern]
    for k in keys:
        vals = _as_list((claims or {}).get(k))
        if not vals:
            return []  # claim absent -> rule cannot match
        results = [re.sub(r"\{\{\s*" + re.escape(k) + r"\s*\}\}", v, r) for r in results for v in vals]
    return results


def applicable_roles(model: Model, auth_method: str, claims: dict) -> list[str]:
    out = []
    for rn, r in model.roles.items():
        for a in r.get("associations") or []:
            if _norm(a.get("auth_method", "")) != _norm(auth_method):
                continue
            cs = str(a.get("case_sensitive", True)).lower() != "false"
            if sub_claims_match(a.get("sub_claims") or {}, claims, cs):
                out.append(rn)
                break
    return out


def effective_capabilities(model: Model, auth_method: str, claims: dict, path: str,
                           obj_type: str = "item") -> tuple[set[str], list[str]]:
    """Return (capabilities, explanation lines)."""
    rule_type = TYPE_TO_RULE[obj_type]
    caps: set[str] = set()
    denied = False
    why: list[str] = []
    for rn in applicable_roles(model, auth_method, claims):
        for ru in model.roles[rn].get("rules") or []:
            if ru.get("type", "item-rule") != rule_type:
                continue
            for pat in expand_templates(ru["path"], claims):
                if path_matches(pat, path):
                    rc = set(ru.get("capabilities") or [])
                    why.append(f"{rn}: {pat} -> {sorted(rc)}")
                    if "deny" in rc:
                        denied = True
                    caps |= rc
    if denied:
        return set(), why + ["deny overrides all other permissions"]
    caps.discard("deny")
    if caps & CRUD:
        caps.add("list")
    return caps, why
