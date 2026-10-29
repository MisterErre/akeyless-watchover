"""Fake Akeyless back ends (CLI binary and REST server) answering from the export fixtures.

Both speak the operations listed in akl_export.OPS, so the same fixture data can be read through
--transport cli, --transport api and --from-dir and the outputs compared.
"""
import glob
import json
import os
import re
import sys
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

FX = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures", "export")


def _load(sub):
    return [json.load(open(f)) for f in sorted(glob.glob(os.path.join(FX, sub, "*.json")))]


def _one(name, default):
    p = os.path.join(FX, name)
    return json.load(open(p)) if os.path.exists(p) else default


class NotFound(Exception):
    pass


def respond(op, params):
    """Return the JSON document Akeyless would return for op/params. List operations behave like the CLI:
    one row per page and a `next_page` token on EVERY page, including the last, empty one."""
    def paged(key, rows):
        tok = params.get("pagination-token") or "p0"
        n = int(tok[1:])
        return {key: rows[n:n + 1], "next_page": f"p{n + 1}"}
    if op == "list-roles":
        return paged("roles", [{"role_name": r["role_name"]} for r in _load("roles")])
    if op == "get-role":
        for r in _load("roles"):
            if r["role_name"] == params["name"]:
                return r
        raise NotFound(params["name"])
    if op == "list-auth-methods":
        return paged("auth_methods", [{"auth_method_name": m["auth_method_name"]} for m in _load("auth_methods")])
    if op == "get-auth-method":
        for m in _load("auth_methods"):
            if m["auth_method_name"] == params["name"]:
                return m
        raise NotFound(params["name"])
    if op == "list-items":
        path = "/" + params["path"].strip("/")
        folders = [f for f in _one("folders_discovered.json", []) if os.path.dirname(f.rstrip("/")) == path]
        items = [i for i in _load("items") if os.path.dirname(i["item_name"]) == path]
        rows = [("folders", f + "/") for f in folders] + [("items", i) for i in items]
        n = int((params.get("pagination-token") or "p0")[1:])
        page = {"folders": [], "items": [], "next_page": f"p{n + 1}"}
        for k, v in rows[n:n + 1]:
            page[k].append(v)
        return page
    if op == "folder-get":
        for f in _load("folders"):
            if f["folder"]["folder_name"] == params["name"]:
                return f
        raise NotFound(params["name"])
    if op == "describe-item":
        for i in _load("items"):
            if i["item_name"] == params["name"]:
                return i
        raise NotFound(params["name"])
    if op == "account-custom-field-list":
        return _one("custom_fields.json", [])
    if op == "policy-list":
        return _one("policies.json", {"policies": []})
    if op == "get-account-settings":
        return _one("account_settings.json", {})
    if op == "list-targets":
        return paged("targets", _one("targets.json", []))
    if op == "list-groups":
        return paged("groups", _one("groups.json", []))
    if op == "gateway-get-config":
        return _one("gateway_config.json", {})
    fn = (re.sub(r"[^A-Za-z0-9_.-]", "_", str(params.get("name", "")).strip("/")) or "root") + ".json"
    if op == "target-get-details":
        return _required(os.path.join("targets", fn), params)
    if op == "get-group":
        return _required(os.path.join("groups", fn), params)
    if op in ("gateway-get-defaults", "gateway-get-cache", "gateway-get-remote-access", "gateway-get-log-forwarding"):
        return _required(os.path.join("gateway", op[len("gateway-get-"):].replace("-", "_") + ".json"), params)
    if op == "gateway-list-migration":
        body: dict = {}
        for m in _load(os.path.join("gateway", "migrations")):
            for kind, lst in m["body"].items():
                body.setdefault(kind, []).extend(lst)
        return {"body": body}
    if op == "gateway-get-allowed-access":
        return _required(os.path.join("gateway", "allowed_access", fn), params)
    raise NotFound(op)


def _required(rel, params):
    p = os.path.join(FX, rel)
    if not os.path.exists(p):
        raise NotFound(params.get("name") or rel)
    return json.load(open(p))


# ---------------------------------------------------------------- REST
def serve(log):
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    from akl_export import OPS
    by_path = {path: op for op, (_w, path, _s) in OPS.items()}

    class H(BaseHTTPRequestHandler):
        def do_POST(self):  # noqa: N802
            body = json.loads(self.rfile.read(int(self.headers["Content-Length"])) or "{}")
            path = self.path.replace("/gw/api/v2", "")
            log.append((self.path, body))
            try:
                if body.get("token") != "T0KEN":
                    raise PermissionError
                out, code = respond(by_path[path], {k: v for k, v in body.items() if k != "token"}), 200
            except PermissionError:
                out, code = {"error": "unauthorized"}, 401
            except (NotFound, KeyError):
                out, code = {"error": "not found"}, 404
            data = json.dumps(out).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def log_message(self, *a):
            pass

    srv = HTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


# ---------------------------------------------------------------- CLI
def cli_main(argv):
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    from akl_export import OPS
    log = os.environ.get("FAKE_AKL_LOG")
    if log:
        with open(log, "a") as fh:
            fh.write(json.dumps(argv) + "\n")
    for op, (words, _p, _s) in OPS.items():
        if argv[:len(words)] == words:
            rest = argv[len(words):]
            params, i = {}, 0
            while i < len(rest):
                if rest[i] in ("--json",):
                    i += 1
                    continue
                params[rest[i].lstrip("-")] = rest[i + 1]
                i += 2
            params.pop("profile", None)
            params.pop("gateway-url", None)
            try:
                print(json.dumps(respond(op, params)))
                return 0
            except NotFound as e:
                print(f"not found: {e}", file=sys.stderr)
                return 1
    print(f"unknown command {argv}", file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(cli_main(sys.argv[1:]))
