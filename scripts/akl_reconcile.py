#!/usr/bin/env python3
"""Compare the governance repository (e.g. on GitHub Enterprise) with the live Akeyless configuration.

READ-ONLY towards the repository: it is cloned (or an existing checkout is read), never modified, and
nothing is ever committed or pushed. The result is a set of files for a person to review and commit:

  <out>/REPORT.md        every difference, object by object, with the two ways to resolve it
  <out>/changes.patch    unified diff against the repository (apply with `git apply`, then review)
  <out>/proposed/        the changed model files, complete, at their repository paths
  <out>/imports.tf       import blocks for objects that exist only in Akeyless and are added to the model
  <out>/summary.json     the same result for tools
  <out>/export/          the Akeyless export the comparison used (raw JSON redacted)

Compared: roles (rules, associations, management-plane access), auth methods, folders, custom fields,
key policies. Other objects (PKI issuers, event forwarders, Gateway, account settings, targets) are listed
as "not compared": `terraform plan` against the account is the authoritative drift check for everything.

Differences per object:
  changed          the field exists on both sides with different values      -> proposed (Akeyless value)
  only in Akeyless the field is set in Akeyless but absent from the model     -> listed; proposed with
                                                                                --include-unmodelled
                                                                                (often a provider default)
  only in model    the field is in the model but the export does not show it -> listed only
Objects only in Akeyless are proposed as additions (+ import block); objects only in the model are listed
(not applied yet, or deleted outside Git) and proposed for removal only with --propose-removals.

Examples:
  watchover reconcile --repo-url https://ghe.example.com/platform/akeyless-governance.git --profile akl-readonly
  watchover reconcile --repo-dir ~/src/akeyless-governance --transport api --token "$AKEYLESS_TOKEN"
  watchover reconcile --repo-dir . --export-dir export/          # compare with an earlier export, offline
"""
from __future__ import annotations

import argparse
import datetime
import difflib
import glob
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile

import yaml

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

FAMILIES = {  # family -> (section key in YAML, files that hold it (relative to the model dir), default new file)
    "roles": ("roles", "roles/*.yaml", "roles/imported.yaml"),
    "auth_methods": ("auth_methods", "auth_methods.yaml", "auth_methods.yaml"),
    "folders": ("folders", "folders.yaml", "folders.yaml"),
    "custom_fields": ("custom_fields", "governance.yaml", "governance.yaml"),
    "key_policies": ("key_policies", "governance.yaml", "governance.yaml"),
}
EXPORT_TYPES = "roles,auth-methods,folders,custom-fields,key-policies"
MODEL_ONLY_KEYS = {"allow_root_scope", "allow_external_auth_methods"}   # guard switches, not Akeyless state
NONE_VALUES = (None, "", [], {}, False, "none")
NO_PUSH_URL = "watchover-reconcile-is-read-only"


# ------------------------------------------------------------------------------------------- normalisation
def _norm_rules(rules):
    out = []
    for r in rules or []:
        r = dict(r)
        if r.get("type", "item-rule") == "item-rule":
            r.pop("type", None)
        r["capabilities"] = sorted(str(c) for c in r.get("capabilities") or [])
        out.append(r)
    return sorted(out, key=lambda x: (x.get("type", ""), str(x.get("path"))))


def _norm_assocs(assocs):
    out = []
    for a in assocs or []:
        a = dict(a)
        if a.get("case_sensitive") in (True, "true", None):
            a.pop("case_sensitive", None)
        elif a.get("case_sensitive") == "false":
            a["case_sensitive"] = False
        sc = a.get("sub_claims") or {}
        if sc:
            a["sub_claims"] = {k: sorted(str(x) for x in (v if isinstance(v, list) else str(v).split(",")))
                               for k, v in sc.items()}
        else:
            a.pop("sub_claims", None)
        out.append(a)
    return sorted(out, key=lambda x: str(x.get("auth_method")))


def normalise(family: str, obj: dict) -> dict:
    """Comparable form: defaults and model-only switches removed, lists ordered, *_var secret keys ignored."""
    o = {}
    for k, v in (obj or {}).items():
        if k in MODEL_ONLY_KEYS or k.endswith("_var"):
            continue
        if family == "roles" and k == "rules":
            v = _norm_rules(v)
        elif family == "roles" and k == "associations":
            v = _norm_assocs(v)
        elif isinstance(v, list) and all(isinstance(x, (str, int, float, bool)) for x in v):
            v = sorted(str(x) for x in v)
        elif isinstance(v, str) and v.lower() in ("true", "false"):
            v = v.lower() == "true"
        if v in NONE_VALUES:
            continue
        o[k] = v
    return o


def compare(family: str, model_obj: dict, live_obj: dict) -> dict:
    m, l = normalise(family, model_obj), normalise(family, live_obj)
    return {"changed": {k: (m[k], l[k]) for k in sorted(set(m) & set(l)) if m[k] != l[k]},
            "only_akeyless": {k: l[k] for k in sorted(set(l) - set(m))},
            "only_model": {k: m[k] for k in sorted(set(m) - set(l))}}


# ------------------------------------------------------------------------------------------- YAML text editing
_ENTRY = re.compile(r"^  (?! )(?!#)(\S.*)$")


def _section_bounds(lines: list[str], section: str) -> tuple[int, int] | None:
    start = next((i for i, ln in enumerate(lines) if re.match(rf"^{re.escape(section)}:\s*(#.*)?$", ln)), None)
    if start is None:
        return None
    end = start + 1
    while end < len(lines) and (lines[end].strip() == "" or lines[end].startswith((" ", "#"))):
        end += 1
    while end > start + 1 and (lines[end - 1].strip() == "" or lines[end - 1].startswith("#")):
        end -= 1
    return start, end


def _entry_key(line: str):
    try:
        doc = yaml.safe_load(line.strip())
    except yaml.YAMLError:
        return None
    return next(iter(doc)) if isinstance(doc, dict) and len(doc) == 1 else None


def _entries(lines: list[str], section: str) -> dict[str, tuple[int, int]]:
    """key -> (first line, end line exclusive) of each entry directly under `section:`."""
    b = _section_bounds(lines, section)
    if not b:
        return {}
    starts = [(i, _entry_key(lines[i])) for i in range(b[0] + 1, b[1]) if _ENTRY.match(lines[i])]
    out = {}
    for n, (i, key) in enumerate(starts):
        end = starts[n + 1][0] if n + 1 < len(starts) else b[1]
        while end > i + 1 and (lines[end - 1].strip() == "" or lines[end - 1].lstrip().startswith("#")):
            end -= 1                                 # comments/blank lines before the next entry stay with it
        if key is not None:
            out[str(key)] = (i, end)
    return out


def _render(key: str, obj: dict) -> list[str]:
    text = yaml.safe_dump({key: obj}, sort_keys=False, width=120, default_flow_style=False)
    return ["  " + ln + "\n" for ln in text.splitlines()]


def edit_yaml(text: str, section: str, key: str, obj: dict | None) -> str:
    """Replace (obj), add (new key) or remove (obj None) one entry; the rest of the file stays byte-identical."""
    lines = text.splitlines(keepends=True)
    if lines and not lines[-1].endswith("\n"):
        lines[-1] += "\n"
    ents = _entries(lines, section)
    if key in ents:
        s, e = ents[key]
        lines[s:e] = [] if obj is None else _render(key, obj)
    elif obj is not None:
        b = _section_bounds(lines, section)
        if b is None:
            if lines and lines[-1].strip():
                lines.append("\n")
            lines += [f"{section}:\n"] + _render(key, obj)
        else:
            if b[1] == b[0] + 1 and lines[b[0]].rstrip().endswith("{}"):
                lines[b[0]] = f"{section}:\n"
            lines[b[1]:b[1]] = _render(key, obj)
    new = "".join(lines)
    check = ((yaml.safe_load(new) or {}).get(section) or {})
    if obj is None:
        if key in check:
            raise RuntimeError(f"could not remove {section}.{key}")
    elif check.get(key) != obj:
        raise RuntimeError(f"could not rewrite {section}.{key} safely")
    return new


# ------------------------------------------------------------------------------------------- repository (read-only)
def git(*args, cwd=None) -> str:
    if args and args[0] in ("push", "commit", "merge", "rebase", "reset", "tag"):
        raise RuntimeError(f"refusing to run git {args[0]}: reconcile is read-only")
    res = subprocess.run(["git", *args], cwd=cwd, capture_output=True, text=True)
    if res.returncode != 0:
        raise RuntimeError(f"git {' '.join(args)}: {(res.stderr or res.stdout).strip()}")
    return res.stdout.strip()


def fetch_repo(url: str, ref: str, dest: str) -> dict:
    """Shallow clone of one branch; the push URL is disabled so the clone cannot be pushed by mistake."""
    git("clone", "--quiet", "--depth", "1", "--single-branch", "--branch", ref, url, dest)
    git("remote", "set-url", "--push", "origin", NO_PUSH_URL, cwd=dest)
    return {"url": re.sub(r"//[^/@]+@", "//", url), "ref": ref, "commit": git("rev-parse", "HEAD", cwd=dest)}


def describe_checkout(path: str) -> dict:
    info = {"url": None, "ref": None, "commit": None, "dirty": None}
    try:
        info["commit"] = git("rev-parse", "HEAD", cwd=path)
        info["ref"] = git("rev-parse", "--abbrev-ref", "HEAD", cwd=path)
        info["dirty"] = bool(git("status", "--porcelain", cwd=path))
        remote = git("config", "--get", "remote.origin.url", cwd=path)
        info["url"] = re.sub(r"//[^/@]+@", "//", remote) if remote else None
    except RuntimeError:
        pass                                          # not a git checkout: compare the files as they are
    return info


# ------------------------------------------------------------------------------------------- model loading
def load_repo_model(model_dir: str) -> tuple[dict, dict]:
    """objects[family][name] = obj ; where[family][name] = (relative file, section)."""
    objects = {f: {} for f in FAMILIES}
    where = {f: {} for f in FAMILIES}
    for fam, (section, pattern, _new) in FAMILIES.items():
        files = sorted(glob.glob(os.path.join(model_dir, pattern)))
        for path in files:
            doc = yaml.safe_load(open(path, encoding="utf-8")) or {}
            for name, obj in (doc.get(section) or {}).items():
                if name in objects[fam]:
                    raise ValueError(f"{fam} '{name}' is defined twice in the repository model")
                objects[fam][name] = obj or {}
                where[fam][name] = os.path.relpath(path, model_dir).replace(os.sep, "/")
    return objects, where


def load_export(export_dir: str) -> dict:
    m = os.path.join(export_dir, "model")
    files = {"roles": ("roles/imported.yaml", "roles"), "auth_methods": ("auth_methods.imported.yaml", "auth_methods"),
             "folders": ("folders.imported.yaml", "folders"),
             "custom_fields": ("governance.imported.yaml", "custom_fields"),
             "key_policies": ("governance.imported.yaml", "key_policies")}
    out = {}
    for fam, (rel, section) in files.items():
        p = os.path.join(m, rel)
        doc = (yaml.safe_load(open(p, encoding="utf-8")) or {}) if os.path.exists(p) else {}
        out[fam] = doc.get(section) or {}
    return out


def new_file_for(fam: str, name: str, model_dir: str) -> str:
    if fam == "roles":
        m = re.match(r"^/governance/roles/([^/]+)/", name)
        if m and os.path.exists(os.path.join(model_dir, "roles", f"{m.group(1)}.yaml")):
            return f"roles/{m.group(1)}.yaml"
    return FAMILIES[fam][2]


def import_block(fam: str, name: str, live: dict) -> list[str]:
    h = json.dumps
    if fam == "roles":
        out = [f"import {{\n  to = akeyless_role.this[{h(name)}]\n  id = {h(name)}\n}}\n"]
        for a in live.get("associations") or []:
            am = a["auth_method"]
            out.append(f"import {{\n  to = akeyless_associate_role_auth_method.this[{h(name + '|' + am)}]\n"
                       f"  id = {h(name + ':' + am)}\n}}\n")
        return out
    if fam == "auth_methods":
        return [f"import {{\n  to = akeyless_auth_method_{live.get('type')}.this[{h(name)}]\n  id = {h(name)}\n}}\n"]
    if fam == "folders":
        return [f"import {{\n  to = akeyless_folder.this[{h(name)}]\n  id = {h(name)}\n}}\n"]
    return [f"# {fam} '{name}': import ID is numeric - copy the matching block from export/imports.tf\n"]


# ------------------------------------------------------------------------------------------- reconcile
def reconcile(repo_dir: str, model_path: str, export_dir: str, out: str, include_unmodelled: bool,
              propose_removals: bool, repo_info: dict, source: str) -> dict:
    model_dir = os.path.join(repo_dir, model_path)
    if not os.path.isdir(model_dir):
        raise ValueError(f"model directory not found in the repository: {model_path}")
    repo_objs, where = load_repo_model(model_dir)
    live = load_export(export_dir)
    # custom fields have no name of their own in Akeyless: match them by (name, object_type), keep the repo key
    by_content = {(o.get("name"), o.get("object_type")): k for k, o in repo_objs["custom_fields"].items()}
    live["custom_fields"] = {by_content.get((o.get("name"), o.get("object_type")), k): o
                             for k, o in live["custom_fields"].items()}

    texts: dict[str, str] = {}

    def text_of(rel):
        if rel not in texts:
            p = os.path.join(model_dir, rel)
            texts[rel] = open(p, encoding="utf-8").read() if os.path.exists(p) else ""
        return texts[rel]

    original = {}
    results, imports = [], []
    for fam, (section, _p, _n) in FAMILIES.items():
        names = sorted(set(repo_objs[fam]) | set(live[fam]))
        for name in names:
            in_repo, in_live = name in repo_objs[fam], name in live[fam]
            r = {"family": fam, "name": name, "file": where[fam].get(name)}
            if in_repo and in_live:
                d = compare(fam, repo_objs[fam][name], live[fam][name])
                if not any(d.values()):
                    continue
                r.update(status="different", **d)
                apply = dict(d["changed"])
                if include_unmodelled:
                    apply.update({k: (None, v) for k, v in d["only_akeyless"].items()})
                if apply:
                    new_obj = dict(repo_objs[fam][name])
                    for k, (_old, val) in apply.items():
                        new_obj[k] = live[fam][name][k]
                    rel = where[fam][name]
                    original.setdefault(rel, text_of(rel))
                    texts[rel] = edit_yaml(text_of(rel), section, name, new_obj)
                    r["proposed"] = sorted(apply)
            elif in_live:
                rel = new_file_for(fam, name, model_dir)
                r.update(status="only_akeyless", file=rel, proposed=["add"])
                original.setdefault(rel, text_of(rel))
                texts[rel] = edit_yaml(text_of(rel), section, name, live[fam][name])
                imports += import_block(fam, name, live[fam][name])
            else:
                r.update(status="only_model")
                if propose_removals:
                    rel = where[fam][name]
                    original.setdefault(rel, text_of(rel))
                    texts[rel] = edit_yaml(text_of(rel), section, name, None)
                    r["proposed"] = ["remove"]
            results.append(r)

    # ---- write the deliverables
    shutil.rmtree(out, ignore_errors=True)
    os.makedirs(out)
    patch = []
    for rel in sorted(original):
        if texts[rel] == original[rel]:
            continue
        repo_rel = f"{model_path.strip('/')}/{rel}"
        dst = os.path.join(out, "proposed", repo_rel)
        os.makedirs(os.path.dirname(dst), exist_ok=True)
        with open(dst, "w", encoding="utf-8") as fh:
            fh.write(texts[rel])
        a = f"a/{repo_rel}" if original[rel] else "/dev/null"
        patch += list(difflib.unified_diff(original[rel].splitlines(True), texts[rel].splitlines(True),
                                           a, f"b/{repo_rel}"))
    with open(os.path.join(out, "changes.patch"), "w", encoding="utf-8") as fh:
        fh.writelines(patch)
    if imports:
        with open(os.path.join(out, "imports.tf"), "w", encoding="utf-8") as fh:
            fh.write("# Generated by watchover reconcile: objects that exist only in Akeyless and are added to the\n"
                     "# model by changes.patch. Copy next to terraform/*.tf, plan (imports only), apply, then delete.\n\n"
                     + "\n".join(imports))
    if os.path.abspath(export_dir) != os.path.abspath(os.path.join(out, "export")):
        shutil.copytree(export_dir, os.path.join(out, "export"))
    summary = {"generated": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
               "repository": repo_info, "model_path": model_path, "akeyless_source": source,
               "counts": {s: sum(1 for r in results if r["status"] == s) for s in ("different", "only_akeyless", "only_model")},
               "files_changed": sorted(f"{model_path.strip('/')}/{r}" for r in original if texts[r] != original[r]),
               "results": results}
    with open(os.path.join(out, "summary.json"), "w", encoding="utf-8") as fh:
        json.dump(summary, fh, indent=2, default=str)
    with open(os.path.join(out, "REPORT.md"), "w", encoding="utf-8") as fh:
        fh.write(render_report(summary, bool(imports), include_unmodelled, propose_removals))
    return summary


def _v(x) -> str:
    return "`" + json.dumps(x, sort_keys=True, default=str) + "`"


def render_report(s: dict, has_imports: bool, include_unmodelled: bool, propose_removals: bool) -> str:
    repo, c = s["repository"], s["counts"]
    o = ["# Reconcile report - repository vs Akeyless", "",
         f"- repository: {repo.get('url') or '(local checkout)'}  ref `{repo.get('ref')}`  commit `{repo.get('commit')}`"
         + ("  **(uncommitted local changes included)**" if repo.get("dirty") else ""),
         f"- model: `{s['model_path']}`  -  Akeyless source: {s['akeyless_source']}  -  generated {s['generated']}",
         f"- differences: {c['different']} changed object(s), {c['only_akeyless']} only in Akeyless, "
         f"{c['only_model']} only in the repository", "",
         "Nothing was committed or pushed. Review `changes.patch` (or the complete files in `proposed/`), keep the "
         "hunks you agree with, and commit them yourself through a merge request:", "",
         "```bash", "git switch -c reconcile/<date>", "git apply --3way <out>/changes.patch     # then: git add -p",
         "terraform plan                            # must show only the imports and the changes you kept", "```", "",
         "For each difference, choose:", "",
         "- **Akeyless is right** (an intended change made outside Git): keep the hunk - the model now codifies it.",
         "- **The repository is right** (an unwanted console change): drop the hunk - the next apply reverts Akeyless.",
         ""]
    if not s["results"]:
        o += ["**No differences** in the compared object families.", ""]
    for status, title in (("different", "Changed outside Git"), ("only_akeyless", "Only in Akeyless"),
                          ("only_model", "Only in the repository")):
        rows = [r for r in s["results"] if r["status"] == status]
        if not rows:
            continue
        o += [f"## {title} ({len(rows)})", ""]
        for r in rows:
            o.append(f"### {r['family']} `{r['name']}`" + (f"  - `{s['model_path']}/{r['file']}`" if r.get("file") else ""))
            if status == "different":
                for k, (mv, lv) in r["changed"].items():
                    if isinstance(mv, list) and isinstance(lv, list) and any(isinstance(x, dict) for x in mv + lv):
                        o.append(f"- **{k}** changed:")
                        o += [f"  - only in the repository: {_v(x)}" for x in mv if x not in lv]
                        o += [f"  - only in Akeyless: {_v(x)}" for x in lv if x not in mv]
                    else:
                        o.append(f"- **{k}** changed: repository {_v(mv)} -> Akeyless {_v(lv)}")
                for k, lv in r["only_akeyless"].items():
                    o.append(f"- {k} set only in Akeyless: {_v(lv)}"
                             + ("" if include_unmodelled else " (not proposed: often a default; use --include-unmodelled)"))
                for k, mv in r["only_model"].items():
                    o.append(f"- {k} only in the repository: {_v(mv)} (the export does not show this field - check the plan)")
            elif status == "only_akeyless":
                o.append("- created outside Git: proposed as an addition"
                         + (" + import block in `imports.tf`" if has_imports else ""))
            else:
                o.append("- not found in Akeyless: not applied yet, deleted outside Git, or outside the export filters - "
                         + ("proposed for removal" if propose_removals else "listed only (use --propose-removals)"))
            o.append("")
    o += ["## Not compared", "", "PKI issuers, event forwarders (no list operation in Akeyless), Gateway configuration, "
          "account settings and targets. Run `terraform plan` against the account: it is the authoritative drift "
          "check for every managed object.", ""]
    return "\n".join(o)


# ------------------------------------------------------------------------------------------- CLI
def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    src = ap.add_mutually_exclusive_group(required=True)
    src.add_argument("--repo-url", help="governance repository to clone read-only (GitHub Enterprise HTTPS or SSH URL; "
                                        "uses your git credentials, e.g. `gh auth login --hostname <ghe-host>`)")
    src.add_argument("--repo-dir", help="existing local checkout to compare (read only, never modified)")
    ap.add_argument("--ref", default="main", help="branch to compare with --repo-url")
    ap.add_argument("--model-path", default="terraform/model", help="model directory inside the repository")
    ap.add_argument("--out", default="reconcile", help="output directory (replaced; keep it out of Git)")
    live = ap.add_mutually_exclusive_group()
    live.add_argument("--export-dir", help="use an earlier `watchover export` output instead of exporting now")
    live.add_argument("--from-dir", help="export offline from a raw/ directory (as `export --from-dir`)")
    ap.add_argument("--transport", choices=["cli", "api"], default="cli", help="how to read Akeyless (as `export`)")
    ap.add_argument("--profile", help="cli transport: akeyless CLI profile (a read-only identity is enough)")
    ap.add_argument("--akeyless", default="akeyless", help="cli transport: path to the akeyless CLI binary")
    ap.add_argument("--api", help="api transport: API URL (default $AKEYLESS_API or https://api.akeyless.io)")
    ap.add_argument("--token", help="api transport: Akeyless token (default $AKEYLESS_TOKEN)")
    ap.add_argument("--only", help="compare only objects whose name matches this regex")
    ap.add_argument("--exclude", action="append", default=[], help="regex of names to skip (repeatable)")
    ap.add_argument("--include-unmodelled", action="store_true",
                    help="also propose fields set in Akeyless but absent from the model")
    ap.add_argument("--propose-removals", action="store_true",
                    help="propose removing objects that are in the repository but not in Akeyless")
    return ap


def main(argv: list[str] | None = None) -> None:
    a = build_parser().parse_args(argv)
    a.out = a.out.rstrip("/") or "."
    work = tempfile.mkdtemp(prefix="wo-reconcile-")
    try:
        if a.repo_url:
            repo_dir = os.path.join(work, "repo")
            info = fetch_repo(a.repo_url, a.ref, repo_dir)
        else:
            repo_dir = os.path.abspath(os.path.expanduser(a.repo_dir))
            info = describe_checkout(repo_dir)
        if a.export_dir:
            export_dir, source = a.export_dir, f"earlier export `{a.export_dir}`"
        else:
            import akl_export
            export_dir = os.path.join(work, "export")
            args = ["--out", export_dir, "--types", EXPORT_TYPES]
            if a.from_dir:
                args += ["--from-dir", a.from_dir]
                source = f"offline replay `{a.from_dir}`"
            else:
                args += ["--transport", a.transport, "--akeyless", a.akeyless]
                for flag, val in (("--profile", a.profile), ("--api", a.api), ("--token", a.token)):
                    if val:
                        args += [flag, val]
                source = f"live export ({a.transport}{', profile ' + a.profile if a.profile else ''})"
            if a.only:
                args += ["--only", a.only]
            for x in a.exclude:
                args += ["--exclude", x]
            akl_export._main(args)
        s = reconcile(repo_dir, a.model_path, export_dir, a.out, a.include_unmodelled, a.propose_removals, info, source)
        c = s["counts"]
        print(f"reconcile: {c['different']} changed, {c['only_akeyless']} only in Akeyless, "
              f"{c['only_model']} only in the repository; {len(s['files_changed'])} file(s) in the proposal")
        print(f"review {a.out}/REPORT.md and {a.out}/changes.patch - nothing was committed or pushed")
        sys.exit(1 if any(c.values()) else 0)
    except (RuntimeError, ValueError, OSError, yaml.YAMLError) as e:
        print(f"error: {e}", file=sys.stderr)
        sys.exit(2)
    finally:
        shutil.rmtree(work, ignore_errors=True)


if __name__ == "__main__":
    main()
