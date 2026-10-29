#!/usr/bin/env python3
"""MCP server for akeyless-watchover: the kit, the documentation and the skill commands over stdio.

Any MCP client (Claude Desktop/Code, OpenAI Codex, GitHub Copilot / VS Code, Cursor, Gemini CLI and
others) can use akeyless-watchover through it, whichever model runs the client:

  tools      watchover_<command> for every kit command (arguments generated from the command's options);
             commands that call Akeyless are only listed when WATCHOVER_MCP_LIVE=1
  resources  watchover://skill/SKILL.md (the skill instructions), watchover://docs/<file>.md,
             watchover://model/<file>.yaml (the YAML model of the kit root)
  prompts    one per skill command (design, change, review, ...): the skill instructions + your request

No third-party dependency: JSON-RPC 2.0 over stdin/stdout, one message per line (MCP stdio transport).
Configure the client to start:  python3 <repo>/scripts/watchover_mcp.py   (or: scripts/watchover mcp)
"""
from __future__ import annotations

import argparse
import glob
import json
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import watchover as wo  # noqa: E402

PROTOCOL_VERSIONS = ["2025-11-25", "2025-06-18", "2025-03-26", "2024-11-05"]
NOT_EXPOSED = {"mcp", "install-skill"}          # serving itself / writing outside the kit root
MAX_OUTPUT = 100_000
TIMEOUT = 1800

# MCP tool annotations (hints for clients deciding whether to ask the user before a call)
ANNOTATIONS = {
    "simulate": {"readOnlyHint": True, "openWorldHint": False},
    "validate-skill": {"readOnlyHint": True, "openWorldHint": False},
    "help": {"readOnlyHint": True, "openWorldHint": False},
    "verify": {"readOnlyHint": True, "openWorldHint": True},
    "token": {"readOnlyHint": True, "openWorldHint": True},
    "export": {"readOnlyHint": False, "destructiveHint": False, "openWorldHint": True},
    "account-settings": {"readOnlyHint": False, "destructiveHint": True, "openWorldHint": True},
    "forwarder": {"readOnlyHint": False, "destructiveHint": False, "openWorldHint": False},
    "conjur": {"readOnlyHint": False, "destructiveHint": False, "openWorldHint": False},
    "build-skill": {"readOnlyHint": False, "destructiveHint": True, "openWorldHint": False},
    "test": {"readOnlyHint": False, "destructiveHint": False, "openWorldHint": False},
}


def repo_root() -> str:
    return os.path.abspath(os.path.expanduser(os.environ.get("WATCHOVER_REPO") or os.path.dirname(HERE)))


def live_enabled() -> bool:
    return os.environ.get("WATCHOVER_MCP_LIVE", "") in ("1", "true", "yes")


# ------------------------------------------------------------------------------------------ tools
def _help_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(prog="watchover help")
    ap.add_argument("topic", nargs="?", help="a kit command name or 'skill'; empty = overview")
    return ap


def exposed_tools() -> list[tuple[str, str, argparse.ArgumentParser, bool]]:
    """(command, summary, parser, needs_akeyless) for every command the server offers."""
    out = [("help", "Show the kit and skill command reference (same as `watchover help`).", _help_parser(), False)]
    for t in wo.TOOLS:
        if t.name in NOT_EXPOSED or (t.needs_akeyless and not live_enabled()):
            continue
        out.append((t.name, t.summary, t.parser(), t.needs_akeyless))
    return out


def _prop(act: argparse.Action) -> dict:
    desc = (act.help or "").replace("%(default)s", str(act.default))
    if act.nargs == 0:
        return {"type": "boolean", "description": desc}
    item = {"type": "integer"} if act.type is int else {"type": "string"}
    if act.choices:
        item["enum"] = list(act.choices)
    if isinstance(act, argparse._AppendAction) or act.nargs in ("+", "*"):  # noqa: SLF001
        return {"type": "array", "items": item, "description": desc}
    return {**item, "description": desc}


def input_schema(parser: argparse.ArgumentParser) -> dict:
    props, required = {}, []
    for act in parser._actions:  # noqa: SLF001 - argparse has no public API for this
        if isinstance(act, argparse._HelpAction):  # noqa: SLF001
            continue
        props[act.dest] = _prop(act)
        if act.required or (not act.option_strings and act.nargs not in ("?", "*")):
            required.append(act.dest)
    schema = {"type": "object", "properties": props, "additionalProperties": False}
    if required:
        schema["required"] = required
    return schema


def to_argv(parser: argparse.ArgumentParser, args: dict) -> list[str]:
    known = {a.dest: a for a in parser._actions if not isinstance(a, argparse._HelpAction)}  # noqa: SLF001
    unknown = set(args) - set(known)
    if unknown:
        raise ValueError(f"unknown argument(s): {sorted(unknown)}")
    argv: list[str] = []
    positionals: list[str] = []
    for dest, act in known.items():
        if dest not in args or args[dest] is None:
            continue
        val = args[dest]
        if not act.option_strings:
            positionals += [str(v) for v in val] if isinstance(val, list) else [str(val)]
            continue
        flag = next((o for o in act.option_strings if o.startswith("--")), act.option_strings[0])
        if act.nargs == 0:
            if val is True:
                argv.append(flag)
        elif isinstance(val, list):
            for v in val:
                argv += [flag, str(v)]
        else:
            argv += [flag, str(val)]
    return argv + (["--"] + positionals if positionals and any(p.startswith("-") for p in positionals) else positionals)


def list_tools() -> list[dict]:
    tools = []
    for name, summary, parser, live in exposed_tools():
        desc = summary + (" Calls the Akeyless API with your credentials." if live else " Offline.")
        if parser.description and parser.description.strip() != summary:
            desc += "\n\n" + parser.description.strip()
        tool = {"name": "watchover_" + name.replace("-", "_"), "title": f"watchover {name}",
                "description": desc, "inputSchema": input_schema(parser)}
        if name in ANNOTATIONS:
            tool["annotations"] = ANNOTATIONS[name]
        tools.append(tool)
    return tools


def call_tool(tool_name: str, args: dict) -> dict:
    by_name = {"watchover_" + n.replace("-", "_"): (n, p) for n, _s, p, _l in exposed_tools()}
    if tool_name not in by_name:
        raise KeyError(tool_name)
    cmd, parser = by_name[tool_name]
    argv = to_argv(parser, args or {})
    root = repo_root()
    entry = os.path.join(root, "scripts", "watchover.py")
    if not os.path.exists(entry):
        return _text(f"no kit at {root} (scripts/watchover.py missing) - set WATCHOVER_REPO", True)
    try:
        res = subprocess.run([sys.executable, entry, cmd, *argv], cwd=root, capture_output=True, text=True,
                             timeout=TIMEOUT, stdin=subprocess.DEVNULL)
    except subprocess.TimeoutExpired:
        return _text(f"watchover {cmd} timed out after {TIMEOUT}s", True)
    out = (res.stdout or "") + (("\n[stderr]\n" + res.stderr) if res.stderr else "")
    if len(out) > MAX_OUTPUT:
        out = out[:MAX_OUTPUT // 2] + f"\n[... {len(out) - MAX_OUTPUT} characters omitted ...]\n" + out[-MAX_OUTPUT // 2:]
    header = f"$ scripts/watchover {cmd} {' '.join(argv)}".rstrip() + f"\n(exit code {res.returncode})\n\n"
    return _text(header + out, res.returncode != 0)


def _text(text: str, is_error: bool = False) -> dict:
    return {"content": [{"type": "text", "text": text}], "isError": is_error}


# ------------------------------------------------------------------------------------------ resources
def _resource_files() -> dict[str, tuple[str, str, str]]:
    """uri -> (path, mime type, description)."""
    root = repo_root()
    out = {}
    skill = next((p for p in (os.path.join(root, "skill", "akeyless-watchover", "SKILL.md"),
                              os.path.join(os.path.dirname(root), "SKILL.md")) if os.path.isfile(p)), None)
    if skill:
        out["watchover://skill/SKILL.md"] = (skill, "text/markdown", "The akeyless-watchover skill instructions")
    docs = os.path.join(root, "docs") if os.path.isdir(os.path.join(root, "docs")) else \
        os.path.join(os.path.dirname(root), "references")
    for f in sorted(glob.glob(os.path.join(docs, "*.md"))):
        out[f"watchover://docs/{os.path.basename(f)}"] = (f, "text/markdown", "Reference: " + os.path.basename(f))
    model = os.path.join(root, "terraform", "model")
    for f in sorted(glob.glob(os.path.join(model, "**", "*.yaml"), recursive=True)):
        rel = os.path.relpath(f, model).replace(os.sep, "/")
        out[f"watchover://model/{rel}"] = (f, "application/yaml", "Governance model file " + rel)
    return out


def list_resources() -> list[dict]:
    return [{"uri": u, "name": u.split("://", 1)[1], "description": d, "mimeType": m}
            for u, (_p, m, d) in _resource_files().items()]


def read_resource(uri: str) -> dict:
    files = _resource_files()
    if uri not in files:
        raise KeyError(uri)
    path, mime, _d = files[uri]
    return {"contents": [{"uri": uri, "mimeType": mime, "text": open(path, encoding="utf-8").read()}]}


# ------------------------------------------------------------------------------------------ prompts
def list_prompts() -> list[dict]:
    return [{"name": f"watchover-{c.name}", "title": f"akeyless-watchover {c.name}",
             "description": f"{c.purpose} Delivers: {c.delivers}",
             "arguments": [{"name": "request", "description": c.args, "required": c.args.startswith("<")}]}
            for c in wo.SKILL_COMMANDS]


def get_prompt(name: str, args: dict) -> dict:
    cmd = next((c for c in wo.SKILL_COMMANDS if f"watchover-{c.name}" == name), None)
    if cmd is None:
        raise KeyError(name)
    req = (args or {}).get("request", "")
    if cmd.args.startswith("<") and not req:
        raise ValueError(f"argument 'request' is required: {cmd.args}")
    files = _resource_files()
    skill = open(files["watchover://skill/SKILL.md"][0], encoding="utf-8").read() if "watchover://skill/SKILL.md" in files \
        else "(skill instructions not found - read the watchover://docs resources)"
    text = (f"Follow the akeyless-watchover skill instructions below. Run its `{cmd.name}` command"
            + (f" with: {req}" if req else "") + f".\nDeliver: {cmd.delivers}\n"
            "Use the watchover_* tools when you need to run the kit, and the watchover://docs/... resources "
            "for references. Never claim results you did not obtain.\n\n<skill-instructions>\n"
            + skill + "\n</skill-instructions>")
    return {"description": cmd.purpose, "messages": [{"role": "user", "content": {"type": "text", "text": text}}]}


# ------------------------------------------------------------------------------------------ JSON-RPC
INSTRUCTIONS = ("akeyless-watchover: Akeyless governance as code (paths, roles, auth methods, sub-claims, Terraform). "
                "Read watchover://skill/SKILL.md before working on an Akeyless governance task and follow it. "
                "Tools run the kit (scripts/watchover) in the kit root; prompts start a skill command.")


def handle(msg: dict) -> dict | None:
    method, mid, params = msg.get("method"), msg.get("id"), msg.get("params") or {}
    if mid is None:                      # notification (e.g. notifications/initialized): no response
        return None
    try:
        if method == "initialize":
            requested = params.get("protocolVersion")
            result = {"protocolVersion": requested if requested in PROTOCOL_VERSIONS else PROTOCOL_VERSIONS[0],
                      "capabilities": {"tools": {"listChanged": False}, "resources": {"listChanged": False},
                                       "prompts": {"listChanged": False}},
                      "serverInfo": {"name": "watchover-mcp", "title": "akeyless-watchover", "version": wo.VERSION},
                      "instructions": INSTRUCTIONS}
        elif method == "ping":
            result = {}
        elif method == "tools/list":
            result = {"tools": list_tools()}
        elif method == "tools/call":
            try:
                result = call_tool(params.get("name", ""), params.get("arguments") or {})
            except ValueError as e:
                result = _text(f"invalid arguments: {e}", True)
        elif method == "resources/list":
            result = {"resources": list_resources()}
        elif method == "resources/templates/list":
            result = {"resourceTemplates": []}
        elif method == "resources/read":
            result = read_resource(params.get("uri", ""))
        elif method == "prompts/list":
            result = {"prompts": list_prompts()}
        elif method == "prompts/get":
            result = get_prompt(params.get("name", ""), params.get("arguments") or {})
        else:
            return {"jsonrpc": "2.0", "id": mid, "error": {"code": -32601, "message": f"method not found: {method}"}}
    except KeyError as e:
        return {"jsonrpc": "2.0", "id": mid, "error": {"code": -32602, "message": f"unknown name: {e.args[0]}"}}
    except ValueError as e:
        return {"jsonrpc": "2.0", "id": mid, "error": {"code": -32602, "message": str(e)}}
    return {"jsonrpc": "2.0", "id": mid, "result": result}


def serve(stdin=None, stdout=None) -> None:
    stdin, stdout = stdin or sys.stdin, stdout or sys.stdout
    for line in stdin:
        line = line.strip()
        if not line:
            continue
        try:
            msg = json.loads(line)
        except json.JSONDecodeError:
            resp = {"jsonrpc": "2.0", "id": None, "error": {"code": -32700, "message": "parse error"}}
        else:
            batch = msg if isinstance(msg, list) else [msg]
            resps = [r for r in (handle(m) for m in batch if isinstance(m, dict)) if r is not None]
            resp = resps if isinstance(msg, list) else (resps[0] if resps else None)
        if resp:
            stdout.write(json.dumps(resp) + "\n")
            stdout.flush()


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(prog="watchover mcp", description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--repo", help="kit root the tools run in and the model/docs are read from "
                                   "(default: $WATCHOVER_REPO or this repository)")
    ap.add_argument("--live", action="store_true",
                    help="also expose the commands that call Akeyless (same as WATCHOVER_MCP_LIVE=1)")
    ap.add_argument("--list", action="store_true", help="print the tools, resources and prompts, then exit")
    return ap


def main(argv: list[str] | None = None) -> None:
    a = build_parser().parse_args(argv)
    if a.repo:
        os.environ["WATCHOVER_REPO"] = a.repo
    if a.live:
        os.environ["WATCHOVER_MCP_LIVE"] = "1"
    if a.list:
        print("tools:     " + ", ".join(t["name"] for t in list_tools()))
        print("resources: " + ", ".join(r["uri"] for r in list_resources()))
        print("prompts:   " + ", ".join(p["name"] for p in list_prompts()))
        return
    serve()


if __name__ == "__main__":
    main()
