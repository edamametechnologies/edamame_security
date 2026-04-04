# Agent Plugins

EDAMAME Security provides runtime behavioral monitoring for AI agents through
four integration packages. Each package bridges an agent's reasoning plane
(transcripts, tool calls, session history) to EDAMAME's system-plane observer,
enabling two-plane divergence detection.

## Repositories

| Plugin | Repository | Target | Visibility |
|--------|-----------|--------|------------|
| EDAMAME for Cursor | [edamame_cursor](https://github.com/edamametechnologies/edamame_cursor) | Cursor IDE | Public |
| EDAMAME for Claude Code | [edamame_claude_code](https://github.com/edamametechnologies/edamame_claude_code) | Claude Code CLI | Public |
| EDAMAME for Claude Desktop | [edamame_claude_desktop](https://github.com/edamametechnologies/edamame_claude_desktop) | Claude Desktop app (Code-in-Desktop + Cowork) | Public |
| EDAMAME for OpenClaw | [edamame_openclaw](https://github.com/edamametechnologies/edamame_openclaw) | OpenClaw agents | Public |

Supporting repositories:

| Repository | Purpose | Visibility |
|-----------|---------|------------|
| [agent_security](https://github.com/edamametechnologies/agent_security) | Research paper and benchmark harness (arXiv) | Public |
| [edamame_core_api](https://github.com/edamametechnologies/edamame_core_api) | Public API documentation for the core engine | Public |
| [edamame_posture](https://github.com/edamametechnologies/edamame_posture) | CLI tool for security posture, plugin provisioning, and MCP hosting | Public |

## Two-Plane Architecture

Every plugin implements the same architectural pattern:

```
Reasoning Plane (agent)             System Plane (EDAMAME)
+------------------------------+    +-------------------------------+
| Agent produces transcripts   |    | Packet capture + L7 process   |
| (tool calls, commands, text) |    | attribution (flodbadd)        |
+------------------------------+    +-------------------------------+
            |                                    |
            v                                    v
+------------------------------+    +-------------------------------+
| Plugin extrapolator parses   |    | Session tracking, ML anomaly  |
| transcripts, builds payload  |    | detection, blacklist matching |
+------------------------------+    +-------------------------------+
            |                                    |
            +----------> EDAMAME Core <----------+
                              |
                    +---------+---------+
                    |                   |
            Behavioral Model    Live Telemetry
                    |                   |
                    v                   v
              +---------------------------+
              | Divergence Engine         |
              | Compare intent vs reality |
              +---------------------------+
                         |
                         v
                  Verdict: CLEAN | DIVERGENCE | NO_MODEL | STALE
```

The plugin never stores security state. EDAMAME Core is the single source of
truth for scores, verdicts, behavioral models, and session data.

## Producer Modes

Two additive reasoning-plane producer contracts exist:

| Mode | API | LLM Cost | Used By |
|------|-----|----------|---------|
| **Raw session ingest** | `upsert_behavioral_model_from_raw_sessions` | EDAMAME-side LLM | Cursor, Claude Code, Claude Desktop, OpenClaw (compiled) |
| **Direct model upsert** | `upsert_behavioral_model` | Agent-side LLM | OpenClaw (llm mode) |

Raw session ingest is preferred for production: the plugin sends transcript
text and metadata, and EDAMAME's configured LLM provider generates the
behavioral predictions internally. This eliminates per-cycle LLM cost on
the agent side.

## Package Layout

All four plugins share a common directory structure:

```
bridge/                  Local stdio MCP bridge + forwarding
adapters/                Transcript parsing and payload assembly
service/                 Extrapolator, verdict reader, posture facade, health
setup/                   Install scripts, config templates, health check
  install.sh             Portable local install (bash)
  install.ps1            Portable local install (PowerShell, Windows)
demo/                    CVE/divergence trigger scripts for E2E testing
scripts/                 E2E intent injection test
docs/                    Architecture, setup, operator guidance
tests/                   Unit tests
```

Agent-specific additions:

| Plugin | Extra directories |
|--------|-------------------|
| Cursor | `.cursor-plugin/`, `rules/`, `skills/`, `agents/`, `commands/`, `assets/` |
| Claude Code | `.claude-plugin/`, `skills/`, `agents/`, `commands/`, `assets/` |
| Claude Desktop | `skills/`, `agents/`, `commands/` |
| OpenClaw | `extensions/edamame/` (MCP plugin), `skill/` (OpenClaw skill format) |

## Installation

Multiple installation paths exist for every plugin, ordered by preference:

### 1. EDAMAME app / posture CLI (recommended)

Cross-platform. Downloads the latest release from GitHub as a zipball and
installs using native Rust file operations. No `git`, `bash`, or `python`
required.

```bash
edamame-posture install-agent-plugin cursor
edamame-posture install-agent-plugin claude_code
edamame-posture install-agent-plugin claude_desktop
edamame-posture install-agent-plugin openclaw
```

For Cursor, Claude Code, and Claude Desktop, the provisioning engine
automatically registers the `edamame` MCP server entry in the IDE's global
configuration file (`~/.cursor/mcp.json` for Cursor, `~/.claude.json` for
Claude Code and Claude Desktop, plus the Claude Desktop Electron app config).
Existing servers in those files are preserved. No manual MCP registration
step is needed.

The EDAMAME Security app exposes the same functionality in AI Settings with
one-click install, status display, and intent injection test buttons.

### 2. Marketplace

| Plugin | Command |
|--------|---------|
| Cursor | Search "EDAMAME Security" in Cursor Marketplace |
| Claude Code | `/plugin marketplace add edamametechnologies/edamame_claude_code` |
| Claude Desktop | Install via EDAMAME app or `edamame-posture install-agent-plugin claude_desktop` |
| OpenClaw | `openclaw plugins enable edamame` (after manual copy) |

### 3. Manual install from source

```bash
# Cursor
cd edamame_cursor && bash setup/install.sh /path/to/workspace

# Claude Code
cd edamame_claude_code && bash setup/install.sh /path/to/workspace

# Claude Desktop
cd edamame_claude_desktop && bash setup/install.sh /path/to/workspace

# OpenClaw
cd edamame_openclaw && bash setup/install.sh
```

## Install Paths

| Plugin | Install directory (macOS) |
|--------|---------------------------|
| Cursor | `~/Library/Application Support/cursor-edamame/` |
| Claude Code | `~/Library/Application Support/claude-code-edamame/` |
| Claude Desktop | `~/Library/Application Support/claude-desktop-edamame/` |
| OpenClaw | `~/.openclaw/edamame-openclaw/` |

Each plugin has a `state/` subdirectory for pairing credentials and
operational metadata:

| Plugin | State directory (macOS) |
|--------|-------------------------|
| Cursor | `~/Library/Application Support/cursor-edamame/state/` |
| Claude Code | `~/Library/Application Support/claude-code-edamame/state/` |
| Claude Desktop | `~/Library/Application Support/claude-desktop-edamame/state/` |
| OpenClaw | `~/.openclaw/edamame-openclaw/state/` |

## Pairing

Pairing authenticates the plugin with the EDAMAME MCP endpoint. The
credential is stored as `edamame-mcp.psk` in the plugin's state directory.

### App-mediated pairing (macOS / Windows)

The EDAMAME Security app hosts the MCP server. Pairing uses an HTTP
handshake: the plugin posts a request, the user approves in the app, and
the credential is returned and stored automatically.

| Plugin | How to pair |
|--------|------------|
| Cursor | Call `edamame_cursor_control_center` MCP tool from within Cursor |
| Claude Code | Call `edamame_claude_code_control_center` MCP tool within Claude Code |
| Claude Desktop | Call `edamame_claude_desktop_control_center` MCP tool within Claude Desktop |
| OpenClaw | `bash setup/pair.sh` (from the [edamame_openclaw](https://github.com/edamametechnologies/edamame_openclaw) repo) |

### Shared PSK (Linux / CLI / VM)

When `edamame_posture` is the MCP host, generate a PSK and start the MCP
endpoint:

```bash
edamame-posture mcp-generate-psk
edamame-posture mcp-start 3000 "<PSK>"
```

The `background-mcp-*` and `mcp-*` command forms are aliases -- both work.

Write the PSK to the plugin's state directory or to `~/.edamame_psk`
(legacy shared path).

### Credential lookup order

All four plugins resolve credentials in the same order:

1. `EDAMAME_MCP_PSK` environment variable
2. Plugin-specific `state/edamame-mcp.psk` file
3. `~/.edamame_psk` (legacy shared PSK, OpenClaw only)

## Uninstall

Uninstalling removes all plugin files, config, state, and pairing
credentials. For Cursor, Claude Code, and Claude Desktop, the `edamame` MCP
server entry is also removed from the IDE's global configuration file
(`~/.cursor/mcp.json`, `~/.claude.json`, or the Claude Desktop Electron app
config), leaving other servers intact.

```bash
edamame-posture uninstall-agent-plugin cursor
edamame-posture uninstall-agent-plugin claude_code
edamame-posture uninstall-agent-plugin claude_desktop
edamame-posture uninstall-agent-plugin openclaw
```

## Scope Filters

Each plugin tells the divergence engine which network sessions belong to its
agent using scope path patterns. Sessions matching these patterns are
evaluated against the behavioral model; unmatched sessions are ignored.

| Plugin | Scope level | Example patterns |
|--------|------------|-----------------|
| Cursor | `scope_parent_paths` | `*/Cursor.app/Contents/MacOS/Cursor`, `*/Cursor Helper*` |
| Claude Code | `scope_parent_paths` | `*/claude`, `*/Claude.app/Contents/MacOS/Claude` |
| Claude Desktop | `scope_parent_paths` | `*/Claude.app/Contents/MacOS/Claude`, `*/Claude.exe`, `*/claude_desktop_edamame_mcp.mjs` |
| OpenClaw | `scope_any_lineage_paths` | `*/openclaw-gateway`, `*/bin/openclaw` |

Claude Desktop uses `scope_parent_paths` because the Desktop app is always
the direct parent of network-active subprocesses (including Node.js children
spawned by the MCP bridge).

OpenClaw uses `scope_any_lineage_paths` (matches at any process lineage
level) because the gateway can appear as parent or grandparent depending on
tool-chain depth.

## Provisioning Internals

The Rust provisioning code in
[edamame_foundation](https://github.com/edamametechnologies/edamame_foundation)
(`src/agent_plugin.rs`) is the canonical implementation used by the EDAMAME
app and `edamame_posture` CLI. It handles:

- Downloading the latest zipball from GitHub
- Extracting and copying files to the correct install paths
- Creating config, state, and rendered directories
- Rendering config templates with workspace-specific values
- Automatically injecting the `edamame` MCP server entry into the IDE's global config (`~/.cursor/mcp.json` for Cursor, `~/.claude.json` for Claude Code and Claude Desktop, plus the Claude Desktop Electron app config), preserving existing servers
- Setting file permissions (executable bits for `.mjs` and `.sh` files)
- Chowning installed files to the real user when running as root (helper daemon)

On uninstall, the `edamame` entry is removed from the global MCP config
before deleting the plugin directory tree. Both injection and removal are
non-fatal: failures are logged as warnings but do not prevent the
install/uninstall from succeeding.

### Consistency invariant

The Rust `install_*()` / `uninstall_*()` functions in `agent_plugin.rs` and
the `setup/install.sh` scripts in each plugin repo MUST produce identical
directory structures and file layouts. When modifying one, verify the other.

Key checkpoints:
- Same directories created
- Same files copied
- Same state subdirectory structure
- Same MCP server entry injected into the IDE global config
- Uninstall removes the same tree and the global MCP entry

### Root ownership fix

When the helper daemon installs plugins as root (via `sudo`), all created
files would be root-owned, preventing user-level scripts (pairing, runtime)
from writing to them. The Rust provisioning code includes a `chown` step
that re-assigns ownership to the real user by stat-ing the home directory
to obtain the correct uid/gid.

## Behavioral Model Contract

| Property | Cursor | Claude Code | Claude Desktop | OpenClaw |
|----------|--------|-------------|----------------|----------|
| `agent_type` | `cursor` | `claude_code` | `claude_desktop` | `openclaw` |
| `agent_instance_id` | `<hostname>-<workspace_hash>` | `<hostname>-<workspace_hash>` | `<hostname>-<workspace_hash>` | Stable ID from `~/.edamame_openclaw_agent_instance_id` |
| Ingest API | `upsert_behavioral_model_from_raw_sessions` | `upsert_behavioral_model_from_raw_sessions` | `upsert_behavioral_model_from_raw_sessions` | `upsert_behavioral_model_from_raw_sessions` (compiled) or `upsert_behavioral_model` (llm) |
| Refresh trigger | MCP bridge lifecycle (periodic loop) | MCP bridge lifecycle (periodic loop) | MCP bridge lifecycle (periodic loop) | Cron job (1 min compiled, 5 min llm) |
| Transcript source | `~/.cursor/projects/.../agent-transcripts/` | `~/.claude/projects/` | `~/.claude/projects/` (Code-in-Desktop) + Cowork sessions (platform-specific) | OpenClaw session history API |

## E2E Testing

Two test suites validate each plugin:

| Suite | What it tests | Script |
|-------|--------------|--------|
| **Intent E2E** | Reasoning-plane pipeline: inject synthetic transcripts, verify behavioral predictions | `scripts/e2e_inject_intent.sh` or `tests/e2e_inject_intent.sh` in each repo |
| **CVE / Divergence E2E** | System-plane detection: trigger attack simulations, verify EDAMAME detects them | `demo/trigger_*.py` in each repo |

Run intent tests:

```bash
cd edamame_cursor          && bash scripts/e2e_inject_intent.sh
cd edamame_claude_code     && bash scripts/e2e_inject_intent.sh
cd edamame_claude_desktop  && bash tests/e2e_inject_intent.sh
cd edamame_openclaw        && bash scripts/e2e_inject_intent.sh
```

## Related

| Resource | Link |
|----------|------|
| EDAMAME for Cursor | [github.com/edamametechnologies/edamame_cursor](https://github.com/edamametechnologies/edamame_cursor) |
| EDAMAME for Claude Code | [github.com/edamametechnologies/edamame_claude_code](https://github.com/edamametechnologies/edamame_claude_code) |
| EDAMAME for Claude Desktop | [github.com/edamametechnologies/edamame_claude_desktop](https://github.com/edamametechnologies/edamame_claude_desktop) |
| EDAMAME for OpenClaw | [github.com/edamametechnologies/edamame_openclaw](https://github.com/edamametechnologies/edamame_openclaw) |
| EDAMAME Posture CLI | [github.com/edamametechnologies/edamame_posture](https://github.com/edamametechnologies/edamame_posture) |
| EDAMAME Core API (MCP reference) | [github.com/edamametechnologies/edamame_core_api](https://github.com/edamametechnologies/edamame_core_api) |
| AI Assistant user guide | [AGENTIC.md](AGENTIC.md) |
| Research paper (arXiv) | [github.com/edamametechnologies/agent_security](https://github.com/edamametechnologies/agent_security) |
