# Using akeyless-watchover with any AI agent

akeyless-watchover does not depend on one model or vendor. The same content reaches an agent in three ways.
Use the first one your agent supports:

| Way | What it is | Agents |
|---|---|---|
| **1. Agent Skill** | `SKILL.md` + `references/` + `template/`, in the open [Agent Skills](https://agentskills.io) format | Agents that implement the format: Claude (apps and Claude Code), OpenAI Codex, GitHub Copilot, Cursor, Gemini CLI and others |
| **2. MCP server** | `scripts/watchover_mcp.py`: kit commands as tools, docs and model as resources, skill commands as prompts | Any MCP client that can start a local (stdio) server |
| **3. Prompt pack** | `system-prompt.md` (or the short version) + knowledge files | Chat products and model APIs with no skill or MCP support |

Ways 1 and 2 combine well: the skill gives the agent the method, and the MCP server gives it tools when the
agent has no shell of its own.

## How the skill stays model-neutral

- It uses only the fields of the Agent Skills specification (`name`, `description`, `compatibility`,
  `metadata`). `scripts/watchover validate-skill` checks this, together with the length limits, that the
  name matches the folder, the body length and that every referenced file exists. CI runs the check on
  every change.
- The instructions name no vendor tools. A capability table ("Working in any agent" in `SKILL.md`) tells
  the agent what to do in each case:
  - it can run a shell: run the kit;
  - it has the `watchover_*` MCP tools: call them;
  - it can only read files: read the references and hand over exact commands;
  - it is chat only: answer from the instructions.
- Every case carries the same rule: never claim a result that was not produced.
- The material is found by layout, not by product: `template/` and `references/` in the package, or the
  repository root and `docs/` when the agent works inside the repository.
- Product-specific extras are optional sidecars that other agents ignore. Today there is one:
  `agents/openai.yaml`, which sets the display name, the default prompt and the invocation policy for
  OpenAI Codex and ChatGPT.
- The deterministic work runs in scripts, not in the model: guards, simulation, export, scaffolding and
  tests. Results do not depend on which model calls them.

## 1. Install the skill

Build once (CI also attaches the result to every run as the artefact `akeyless-watchover-skill`):

```bash
scripts/watchover build-skill        # dist/akeyless-watchover/ + .zip, dist/prompt-pack/ + .zip
```

Then install it where your agent looks for skills. `install-skill` builds and copies in one step;
`--scope project` installs into a repository (`--project`, shared with the team through Git), and
`--scope user` installs into your home directory.

| Agent | Command | Folder (project / user) | Invoke explicitly |
|---|---|---|---|
| Claude Code | `scripts/watchover install-skill --agent claude` | `.claude/skills/` / `~/.claude/skills/` | `/akeyless-watchover <command>` |
| Claude apps (web, desktop) | upload `dist/akeyless-watchover.zip` under **Customize > Skills** (code execution enabled) | - | describe the task or name the skill |
| OpenAI Codex (CLI, IDE, app) | `scripts/watchover install-skill --agent codex` | `.agents/skills/` / `~/.agents/skills/` | `$akeyless-watchover` or `/skills` |
| GitHub Copilot (cloud agent, CLI, VS Code agent mode) | `scripts/watchover install-skill --agent copilot` | `.github/skills/` / `~/.copilot/skills/` | describe the task; the CLI also has `/skills` |
| Cursor | `scripts/watchover install-skill --agent cursor` | `.cursor/skills/` / `~/.cursor/skills/` | type `/` in Agent chat and pick the skill |
| Gemini CLI | `scripts/watchover install-skill --agent gemini` | `.gemini/skills/` / `~/.gemini/skills/` | describe the task; `/skills list` to check |
| Other agents using the shared folder | `scripts/watchover install-skill --agent agents` | `.agents/skills/` / `~/.agents/skills/` | as documented by the agent |
| Anything else | `scripts/watchover install-skill --agent custom --dest <skills folder>` | `--dest` | as documented by the agent |

Notes:
- Install for one agent per folder. Some agents also scan other agents' folders (Cursor reads
  `.claude/skills` and `.codex/skills`; Copilot reads `.claude/skills`), so two installations can show the
  skill twice.
- Agents usually discover skills at start-up: restart the agent or reload its skills after installing.
- Skills support is still evolving in some products; some agents need it enabled in their settings
  first (Gemini CLI documented it as experimental). **VERIFY** the folder against your agent's current
  documentation if the skill does not appear.
- `--dry-run` prints the target folder without changing anything; `--force` replaces an existing copy.

## 2. Connect the MCP server

The server needs only Python 3.10+ and pyyaml. Point it at your governance repository (the kit root) with
`--repo` or `WATCHOVER_REPO`. Commands that call Akeyless (`verify`, `export`, `account-settings`, `token`)
are hidden unless you add `--live` (or `WATCHOVER_MCP_LIVE=1`); they then run with the credentials of the
environment the server runs in (CLI profiles, `AKEYLESS_TOKEN`).

What the server offers:

| MCP feature | Content |
|---|---|
| tools | `watchover_help`, `watchover_test`, `watchover_simulate`, `watchover_forwarder`, `watchover_conjur`, `watchover_build_skill`, `watchover_validate_skill`; with `--live` also `watchover_verify`, `watchover_export`, `watchover_account_settings`, `watchover_token`. Arguments are generated from each command's options. |
| resources | `watchover://skill/SKILL.md`, `watchover://docs/<file>.md`, `watchover://model/<file>.yaml` |
| prompts | `watchover-<command>` for every skill command (`watchover-design`, `watchover-change`, ...): the skill instructions plus your request |

Client configuration (replace the paths):

```bash
# Claude Code
claude mcp add watchover -- python3 /path/to/akeyless-watchover/scripts/watchover_mcp.py --repo /path/to/governance-repo
# Gemini CLI
gemini mcp add watchover python3 /path/to/akeyless-watchover/scripts/watchover_mcp.py --repo /path/to/governance-repo
```

```toml
# OpenAI Codex: ~/.codex/config.toml
[mcp_servers.watchover]
command = "python3"
args = ["/path/to/akeyless-watchover/scripts/watchover_mcp.py", "--repo", "/path/to/governance-repo"]
```

```json
// VS Code / GitHub Copilot: .vscode/mcp.json
{ "servers": { "watchover": { "type": "stdio", "command": "python3",
  "args": ["/path/to/akeyless-watchover/scripts/watchover_mcp.py", "--repo", "${workspaceFolder}"] } } }

// Cursor: .cursor/mcp.json - Claude Desktop: claude_desktop_config.json (same shape)
{ "mcpServers": { "watchover": { "command": "python3",
  "args": ["/path/to/akeyless-watchover/scripts/watchover_mcp.py", "--repo", "/path/to/governance-repo"] } } }
```

Check what the server exposes without a client: `scripts/watchover mcp --list`.

Clients that only connect to remote (HTTP) MCP servers, such as web chat products, cannot start this stdio
server directly. Use the skill or the prompt pack there, or put an stdio-to-HTTP bridge of your choice in
front of it. The bridge is not part of this repository; secure it like any service that can run commands
in your repository.

## 3. Use the prompt pack

`dist/prompt-pack/` (also `dist/akeyless-watchover-prompt-pack.zip`):

| File | Where it goes |
|---|---|
| `system-prompt.md` | the system prompt of a model API call, or the instructions field of a project or assistant when there is room for about 18,000 characters |
| `system-prompt-short.md` | instruction fields with a small size limit (about 1,200 characters); it makes the assistant read the knowledge files |
| `knowledge/` | upload as knowledge or project files: `akeyless-watchover-instructions.md` and `references/*.md` |

Examples:
- a ChatGPT project or custom GPT, or a Gemini Gem: short prompt + knowledge files;
- an OpenAI, Gemini or Anthropic API call, or a local model: `system-prompt.md` as the system message.

A chat-only assistant cannot run the kit: it gives you the commands and you run them in your repository.

## Choosing

| You use... | Use |
|---|---|
| a coding agent in your governance repository (Claude Code, Codex, Copilot, Cursor, Gemini CLI) | the skill (project scope), plus the MCP server if the agent has no shell |
| a desktop assistant without a shell (MCP capable) | the MCP server (its prompts carry the skill), plus the skill if the app supports skills |
| a chat product without skills or local MCP | the prompt pack |
| your own application on any model API | `system-prompt.md` as the system prompt; MCP client libraries can attach the server's tools |

Behaviour does not depend on the model, but quality does: smaller models follow long instructions less
reliably. The offline checks are the safety net whatever the model: `watchover test`, `simulate`, the plan
review and the Terraform guards. Every change still goes through them.
