# EDAMAME Security

> **EDAMAME** is the developer-first, agent-first runtime security layer for the SDLC. **EDAMAME Security** protects workstations and local coding sessions, **EDAMAME Posture** secures CI/CD runners, build hosts, and self-hosted agent hosts, **EDAMAME Hub** gives teams fleet visibility and proof, and **EDAMAME Portal** handles account access and managed LLM subscription.

## Overview

EDAMAME Security is your all‑in‑one tool to secure, understand, and prove the security of your development workstation—from OS to network.

**Note: This application is currently closed source. This repository is used for issue tracking and community feedback.**

## Deterministic by Design: What Needs an LLM and What Does Not

EDAMAME's security engine is **deterministic-first**. Discovery, scanning,
benchmarking, ML anomaly detection, agent visibility, and the structural
attack-pattern and divergence detectors all run **locally with no LLM
configured**. A Large Language Model is an **optional enhancement layer** that
adds natural-language explanations, automated remediation decisions, and noise
suppression on top of that deterministic core.

| Capability area | Works with no LLM | What an LLM adds (optional) |
| --- | --- | --- |
| System benchmarks & one-click remediation | Full CIS / SOC 2 / ISO checks, scoring, remediation, rollback | Plain-language advisor report; automated "fix what's safe" decisions |
| Network scanning (LAN) | Host / port / service discovery, CVE lookup, device classification and criticality | RAG-based explanation of device vulnerabilities |
| Traffic monitoring | Capture, L7 process attribution, ML anomaly detection, blacklist matching | RAG-based explanation of suspicious sessions |
| Digital identity | HaveIBeenPwned breach lookup and alerts | RAG-based explanation of breaches |
| **Agent visibility** | Agent inventory, MCP discovery, component inventory, capability graph, host blast radius, governance-harness coverage, OWASP GenAI scorecard, deterministic divergence & attack-pattern detection | Behavioral-intent extrapolation from transcripts; verdict / finding adjudication and explanation |
| AI Assistant (agentic automation) | — (this *is* the LLM layer) | Automated todo triage, remediation, escalation |
| Compliance reports | Signed posture, SOC 2 / ISO 27001 reports, Hub reporting | — |

The only feature that **requires** an LLM is the **AI Assistant** (EDAMAME's
own agentic automation). Everything else degrades gracefully: without a
provider configured you keep full visibility and deterministic detection, and
the optional "AI analysis" controls simply stay disabled until you connect a
provider (Cloud LLM, Claude, OpenAI, or local Ollama).

> ML anomaly detection (traffic) and the deterministic attack-pattern and
> divergence detectors are **not** LLMs — they run on-device with no model
> provider and no data leaving the machine.

## Key Features

### Security Advisor for System and Network Issues
- Holistic security posture report using frontier LLM
- At‑a‑glance view of outstanding issues
- Sort issues by priority and category
- Be notified of new issues in real-time

### Agent Visibility (Agent Detection & Response)

EDAMAME observes the AI coding agents already running on your machine
(Cursor, Claude Code, Claude Desktop, OpenClaw, Codex, Hermes) and turns them
into first-class, governed assets. Most of this is **structural** — on-disk,
in-process, and on-the-wire evidence that needs **no LLM**. It sits *on top of*
EDAMAME's own agentic automation (the AI Assistant) described below.

**Works without an LLM (deterministic):**
- Agent discovery and inventory — agents are detected from their on-disk transcript directories; **no plugin install is required** to be seen
- MCP endpoint discovery and deterministic risk findings
- Agent component inventory (tools, secrets, instruction files)
- Capability graph and trust zones; recursion / delegation detection
- Host blast radius — flags discovered agents that run unsandboxed, with passwordless root, or that drive critical subprocesses
- Governance-harness coverage — flags discovered agents running with **no recognized agent harness** (e.g. [AgentField](https://agentfield.ai), Rippletide) enforcing policy, identity, budget, tool allow-listing, or audit trail; closes the AI agent governance gap
- "Unsecured agent" posture — flags an agent present on disk whose EDAMAME observer has been paused
- Two-plane divergence detection (deterministic floor) — compares declared agent intent against live process / file / network telemetry
- Deterministic attack-pattern detection on agent activity (token exfiltration, credential harvest, sensitive-material egress, sandbox escape, supply-chain, file tampering), plus agent control-plane checks: enforcement-config weakening (an agent turning its own sandbox or permission rules off) and denylist bypass (a denied command re-spelled to get around the rule)
- OWASP GenAI / Agentic Top-10 coverage scorecard

**Enhanced with an LLM (optional):**
- Behavioral-intent extrapolation — EDAMAME's configured provider turns raw agent transcripts into predicted intent for divergence comparison
- Divergence and attack-pattern **adjudication** — the LLM refines and explains the deterministic verdict and suppresses ambient noise, while guard-railed CRITICAL findings are never silenced

The EDAMAME host always stays the verdict authority: the agent plugins observe
and onboard, but they never adjudicate. See [Agent Plugins](#agent-plugins) for
the per-agent integration packages, install paths, and pairing.

### AI Assistant and protection (Agentic System)
- **One protection switch**: the Assistant, attack pattern detection and intent divergence detection are off until you turn them on, together, from the protection capsule under the Security radar (bottom-left: AI, Protection, Auto-fix). **Connect Portal** signs in to the EDAMAME Portal and turns protection on; **Turn on protection** starts it without a model. On desktop protection also starts session capture and file monitoring, and turning it off stops them.
- **Detection runs without a model**: both detectors publish deterministic findings; a connected model adds LLM review of the findings and the Assistant's analysis of your todos.
- **The Assistant** (requires a model) triages the Security todos at one of two levels: **Review** (it recommends, you confirm) or **Auto** (**Auto-fix**: it fixes safe issues on its own and escalates the rest). Every fix can be undone.
- **Two histories** in Security: **Detections** lists every attack-pattern and divergence finding and never changes with the model connection; **AI History** lists the Assistant's actions, appears only while a model is connected, and is cleared when you disconnect the model, so a reconnection starts fresh.
- Supports multiple LLM providers:
  - **Cloud LLM (EDAMAME)** - Managed AI service with OAuth authentication via EDAMAME Portal; free and paying tiers (see [portal.edamame.tech](https://portal.edamame.tech)); optional API keys for headless environments
  - **Claude (Anthropic)** - Detailed reasoning and nuanced security decisions (API key required)
  - **OpenAI (GPT)** - Fast responses and general-purpose analysis (API key required)
  - **Ollama (Local)** - Privacy-focused, runs entirely on your machine (no cloud dependency)
- Complete transparency: AI History with filters, Confirm pending / Undo all, the reasoning of every action and deep links to the related security views; every automated fix can be undone.
- **Model Context Protocol (MCP) integration**:
  - Secure localhost-only server (port 3000) with Streamable HTTP transport (exposed on desktop builds; mobile hides the control)
  - Dual-mode authentication: per-client credentials via app-mediated pairing (desktop clients POST to `/mcp/pair`, user approves in app, client gets `edm_mcp_...` credential) or shared PSK for CLI/headless tools and automation
  - 52 read-oriented tools: security findings, observation (sessions with L7 process attribution, LAN devices, breaches, score), attack-pattern and divergence findings, dismissal rules (read-only), adding a monitored email, and the Assistant's remediation of threats and policies; dismissals, detection on/off and every other observer-state change stay operator-only
  - Sessions include deep L7 enrichment: process lineage, parent chain, open files (sensitive file tracking), temp-origin detection, resource usage
  - Identity monitoring: add emails for HIBP breach monitoring at runtime (removing one is operator-only)
  - First-class agent integrations for runtime behavioral monitoring -- see [Agent Plugins](#agent-plugins) for architecture, install paths, pairing, and E2E testing:
    - [EDAMAME for Cursor](https://github.com/edamametechnologies/edamame_cursor) -- Cursor IDE plugin (Cursor Marketplace)
    - [EDAMAME for Claude Code](https://github.com/edamametechnologies/edamame_claude_code) -- Claude Code plugin (Claude Code Marketplace)
    - [EDAMAME for Claude Desktop](https://github.com/edamametechnologies/edamame_claude_desktop) -- Claude Desktop plugin (Code-in-Desktop and Cowork modes)
    - [EDAMAME for OpenClaw](https://github.com/edamametechnologies/edamame_openclaw) -- OpenClaw agent plugin
    - [EDAMAME for Codex CLI](https://github.com/edamametechnologies/edamame_codex) -- OpenAI Codex CLI plugin
    - [EDAMAME for Hermes](https://github.com/edamametechnologies/edamame_hermes) -- Nous Research Hermes Agent plugin
  - Connect MCP Inspector or build custom workflows
  - Test interactively with MCP Inspector: `npx @modelcontextprotocol/inspector --server-url http://127.0.0.1:3000/mcp --transport http`
  - See [EDAMAME Core API MCP Reference](https://github.com/edamametechnologies/edamame_core_api/blob/main/MCP.md) for complete tool documentation
- See the [AI Assistant — User Guide](#ai-assistant--user-guide) below for detailed workflows and MCP testing instructions

### System Security Benchmarks and One-Click Remediations
- Assess your workstation against industry standards, including:
    - CIS Benchmarks
    - SOC 2 / ISO 27001 compliance requirements
    - Privacy requirements
- Visualize all elements comprising your system attack surface with their status in real-time
- Automatically fix common system security issues without requiring deep security expertise
    - Get a detailed description of each issue
    - Perform one‑click remediations with technical explanations
- Run batch automated remediations to harden your system with one click
- Keep a history of remediations and roll back if needed

### Built‑in Network Scanning (inspired by Nmap)
- Host discovery on local LAN segments
- Gateway and host discovery beyond direct LAN segments (useful for complex LAN setups)
- Fast TCP/UDP port scanning of known service ports
- Automated, safe, rate‑limited cyclic scans
- Service and version detection (HTTP banner analysis)
- Smart service discovery (mDNS)
- MAC address capture and vendor lookup
- CVE lookup for open ports and vendors
- Automated device classification (computers, cameras, routers, etc.)
- Customizable device names
- Device criticality analysis based on open ports and CVEs
- Anonymized, RAG‑based AI analysis of device vulnerabilities
- Flag critical device ports as safe when applicable
- LAN sharing of device metadata (e.g., your PC app feeds your phone app missing metadata like MAC addresses)
- Get notifications for new devices
- Searchable history of network events and seen networks

### Traffic Monitoring (inspired by Wireshark)
- Capture traffic sessions with deep L7 process attribution: process name, path, parent chain, command line, open files, temp‑origin detection, resource usage
- At‑a‑glance, real‑time traffic view using sunburst visualization
- Flexible table view of traffic sessions
- Flag blacklisted traffic
- ML‑based traffic anomaly detection
- Anonymized, RAG‑based AI analysis of suspicious sessions
- Flag suspicious sessions as safe when applicable
- Get notifications for new suspicious sessions
- Searchable history of suspicious sessions

### Digital Identity Management
- Monitor and manage your online identity exposure
- Dynamically add and remove monitored email addresses (also available via MCP for AI agent integration)
- Integrated with [HaveIBeenPwned.com](https://haveibeenpwned.com)
- Anonymized, RAG‑based AI analysis of data breaches
- Flag breaches as safe when properly handled
- Get notifications about data breaches affecting your email accounts

### Compliance Reports
- Compute and anonymously sign your current security posture through EDAMAME's backend
- Generate SOC 2 or ISO 27001 one‑click compliance reports and make them available to third parties (employers, partners, etc.)
- Connect to the no‑MDM platform at [hub.edamame.tech](https://hub.edamame.tech), enabling:
   - Continuously report your security posture without compromising privacy to gain access to protected resources
   - Compatible with identity providers (Google, Microsoft), Git platforms (GitHub, GitLab), VPNs (Tailscale, NetBird), and firewalls (Fortinet)

https://github.com/user-attachments/assets/4221b077-d6e3-4b2c-815f-3b3fd01a9ae7

## Download and Installation

| Feature | macOS | Windows | Linux | iOS | Android/ChromeOS |
| --- | --- | --- | --- | --- | --- |
| System | ✓ | ✓ | ✓ | ✓ | ✓ |
| LAN | ✓ | ✓ | ✓ | ✓ | ✓ |
| Identity | ✓ | ✓ | ✓ | ✓ | ✓ |
| Traffic | ✓ | requires Npcap | ✓ | - | - |
| Helper | mandatory | optional | built-in | none | none |

### macOS

#### Homebrew Installation (Recommended)
The easiest way to install on macOS:

```bash
# Install EDAMAME Security + Helper (required for full system access)
# Fully-qualified names self-trust the EDAMAME tap (Homebrew 6.0.0 Tap Trust)
brew install --cask edamametechnologies/tap/edamame
brew install --cask edamametechnologies/tap/edamame-helper
```

To update to the latest versions:
```bash
brew upgrade --cask edamametechnologies/tap/edamame
brew upgrade --cask edamametechnologies/tap/edamame-helper
```

**Note**: Both packages are required for full functionality. The main app provides the UI, while the helper enables privileged security operations.

#### Mac App Store

Step 1: : Install and Open the app from App Store
- Download from the [Mac App Store](https://apps.apple.com/app/edamame-security/id1636777324) for an Apple-vetted sandboxed app
<img width="550" height="434" alt="Screenshot 2025-12-08 at 5 12 20 PM" src="https://github.com/user-attachments/assets/1daae4f4-1aa9-4ecc-91f0-ff842dc3c409" />

Step 2: Install EDAMAME Helper from Todo action(s)
- Click on this Todo action item for the Helper software…
<img width="723" height="108" alt="Screenshot 2025-12-08 at 5 13 04 PM" src="https://github.com/user-attachments/assets/cfdc89fd-63bc-489a-b3b4-784b26544efe" /><img width="719" height="425" alt="Screenshot 2025-12-08 at 5 15 46 PM" src="https://github.com/user-attachments/assets/3e5f8825-2401-4f50-ae26-b286e4055ab3" />
<br/> and click on "Push to install"

or

- Install directly the EDAMAME Helper manually [EDAMAME Helper](https://github.com/edamametechnologies/edamame_helper/releases) installation for full system access

#### Direct Download
- Download the all-in-one installer: [edamame-latest.pkg](https://edamame.s3.eu-west-1.amazonaws.com/macos/edamame-latest.pkg)
- Includes both the main app and the EDAMAME Helper for complete functionality

### Windows

#### All-in-One Installer (Recommended)

The single signed installer bundles both components in one download: the
**EDAMAME Security** app (UI) and the **EDAMAME Helper** system service (privileged
security operations such as Security Score analysis and remediations). One
double-click, one elevation prompt, both pieces installed.

1. Download: [edamame-latest-setup.exe](https://edamame.s3.eu-west-1.amazonaws.com/windows/edamame-latest-setup.exe)
2. Run the installer and click **Install**.
3. (Optional) Install [Npcap](https://npcap.com/#download) to enable traffic capture.

After install, **Add/Remove Programs** lists two entries:
- **EDAMAME Security** -- the bundle itself; uninstall here to remove both components.
- **EDAMAME Helper** -- the system service. Listed separately so users migrating
  from the previous two-package install (and Microsoft Store users who add the
  helper) keep a familiar Programs and Features layout.

When a new version is available, the in-app updater points at this same
bundle, so upgrading is a one-click operation.

Past releases (per-version, signed) live on the
[edamame_security GitHub Releases page](https://github.com/edamametechnologies/edamame_security/releases),
named `edamame-windows-<version>-setup.exe`.

#### Chocolatey

```powershell
# Install EDAMAME Security app
choco install edamame

# Install EDAMAME Helper (system service)
choco install edamame-helper

# Install Npcap (required for traffic capture)
choco install npcap
```

To update:
```powershell
choco upgrade edamame
choco upgrade edamame-helper
choco upgrade npcap
```

The Chocolatey `edamame` package installs the MSIX-only version of the app,
so the helper must be installed separately via `edamame-helper`. If you'd
rather get both in one shot, use the **All-in-One Installer** above.

#### Microsoft Store

Step 1: Install and open the app from the Microsoft Store.

- Download from the [Microsoft Store](https://www.microsoft.com/store/apps/9N399LMTKQLQ) for a Microsoft-vetted sandboxed app.
<img width="711" height="634" alt="Screenshot Microsoft Store install" src="https://github.com/user-attachments/assets/dd6ccc1d-5959-46cc-99c8-89b724fff014" />
<br>

Step 2: Install EDAMAME Helper.

Microsoft Store apps run in a sandbox, so the Store cannot ship the helper
alongside the app. The easiest path is to let the app prompt you: on the
**Security** radar, open the Helper software item and click "Push to install".
<img width="717" height="146" alt="Screenshot helper Todo action" src="https://github.com/user-attachments/assets/3db8d298-3cf7-4e7c-b452-18cb6ccedb49" />
<img width="724" height="431" alt="Screenshot Push to install" src="https://github.com/user-attachments/assets/c2b23276-1ff4-44d0-b1a6-1ed836e4cc04" />

If you prefer to install the helper manually, download the standalone signed MSI:
[edamame_helper-latest-x86_64.msi](https://edamame.s3.eu-west-1.amazonaws.com/windows/edamame_helper-latest-x86_64.msi).
This is the same MSI shipped inside the All-in-One Installer, so it upgrades
cleanly later if you switch to the bundle. Run it from your Downloads folder
and accept the elevation prompt.

Step 3 (optional): Install [Npcap](https://npcap.com/#download) to enable traffic capture.

#### Direct Download -- Components Only (advanced)

If you cannot run the all-in-one `.exe` (corporate policy, fleet management
tooling that drives MSI/MSIX directly, etc.), install the two pieces
separately from S3 -- same files the bundle ships:

1. App (MSIX): [edamame-latest.msix](https://edamame.s3.eu-west-1.amazonaws.com/windows/edamame-latest.msix)
2. Helper (MSI): [edamame_helper-latest-x86_64.msi](https://edamame.s3.eu-west-1.amazonaws.com/windows/edamame_helper-latest-x86_64.msi)
3. Optional: [Npcap](https://npcap.com/#download) for traffic capture.

### Linux

#### APT Repository (Debian/Ubuntu/Raspbian) - Recommended

> **Raspberry Pi Users**: EDAMAME Security supports Raspberry Pi OS on all models (armhf for 32-bit, arm64 for 64-bit OS).
```bash
# Import GPG key and add repository
wget -O - https://edamame.s3.eu-west-1.amazonaws.com/repo/public.key | sudo gpg --dearmor -o /usr/share/keyrings/edamame.gpg
echo "deb [arch=amd64 signed-by=/usr/share/keyrings/edamame.gpg] https://edamame.s3.eu-west-1.amazonaws.com/repo stable main" | sudo tee /etc/apt/sources.list.d/edamame.list

# Update package list
sudo apt update

# Install EDAMAME Security (GUI app)
sudo apt install edamame-security

# Launch the app
/usr/lib/edamame-security/edamame_security &
```

The `edamame-security` package provides:
- **EDAMAME Security GUI**: Rich graphical interface for security management
- **EDAMAME Posture CLI**: Command-line interface (includes built-in helper)
- Real-time monitoring and notifications
- System tray integration
- GRPC-based communication for hybrid CLI/GUI operation

To update to the latest version:
```bash
sudo apt update
sudo apt upgrade edamame-security
```

#### Individual Components

You can also install individual components separately:

```bash
# Install only EDAMAME Posture CLI (lightweight, no GUI, includes built-in helper)
sudo apt install edamame-posture

# Install only EDAMAME CLI (GRPC client for advanced users)
sudo apt install edamame-cli
```

**Package Architecture**:
- `edamame-security`: GUI app (depends on and uses `edamame-posture`)
- `edamame-posture`: Standalone CLI tool with built-in helper functionality
- `edamame-cli`: GRPC client for remote control of edamame-posture

### Mobile

#### iOS
- Download from the [App Store](https://apps.apple.com/app/edamame-security-mobile/id6448937722)
- No helper required on iOS

#### Android/ChromeOS
- Download from [Google Play Store](https://play.google.com/store/apps/details?id=com.edamametech.edamame)
- No helper required on Android/ChromeOS

## Agent Plugins

> **Most observer features are now internalized into EDAMAME.** The host-side
> transcript observer discovers the AI agents already on your machine and runs
> full two-plane divergence detection **with no plugin installed** — the
> security guarantee lives in EDAMAME core, in the system plane, where a
> compromised agent cannot pause or silence it. The per-agent integration
> packages below are now **optional and additive**: they extend coverage to
> agents the host cannot observe directly (off-host: remote, SSH, container,
> CI runner, VM, or another user account) and provide cooperative onboarding
> (MCP-native pairing, an in-agent read-only posture / verdict surface, health
> checks, and security-awareness rules). They observe and onboard; they never
> adjudicate.

EDAMAME Security provides runtime behavioral monitoring for AI agents through its
**host-side transcript observer** in the core runtime: it correlates each discovered
agent's reasoning plane (transcripts, tool calls, session history) against the system
plane, enabling two-plane divergence detection with **no plugin installed**. The six
integration packages below are **optional and additive** — they extend that observation
to off-host agents and add in-agent onboarding, read-only posture/verdict views, and
(going forward) pre-execution tool-call enforcement.

### Repositories

| Plugin | Repository | Target | Visibility |
|--------|-----------|--------|------------|
| EDAMAME for Cursor | [edamame_cursor](https://github.com/edamametechnologies/edamame_cursor) | Cursor IDE | Public |
| EDAMAME for Claude Code | [edamame_claude_code](https://github.com/edamametechnologies/edamame_claude_code) | Claude Code CLI | Public |
| EDAMAME for Claude Desktop | [edamame_claude_desktop](https://github.com/edamametechnologies/edamame_claude_desktop) | Claude Desktop app (Code-in-Desktop + Cowork) | Public |
| EDAMAME for OpenClaw | [edamame_openclaw](https://github.com/edamametechnologies/edamame_openclaw) | OpenClaw agents | Public |
| EDAMAME for Codex CLI | [edamame_codex](https://github.com/edamametechnologies/edamame_codex) | OpenAI Codex CLI | Public |
| EDAMAME for Hermes | [edamame_hermes](https://github.com/edamametechnologies/edamame_hermes) | Nous Research Hermes Agent | Public |

Supporting repositories:

| Repository | Purpose | Visibility |
|-----------|---------|------------|
| [agent_security](https://github.com/edamametechnologies/agent_security) | Research paper and benchmark harness (arXiv) | Public |
| [edamame_core_api](https://github.com/edamametechnologies/edamame_core_api) | Public API documentation for the core engine | Public |
| [edamame_posture](https://github.com/edamametechnologies/edamame_posture) | CLI tool for security posture, plugin provisioning, and MCP hosting | Public |

### Two-Plane Architecture

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

### Producer Modes

Three additive reasoning-plane producer contracts exist:

| Mode | API | LLM Cost | Driven By |
|------|-----|----------|-----------|
| **Raw session ingest (plugin-driven)** | `upsert_behavioral_model_from_raw_sessions` | EDAMAME-side LLM | Cursor, Claude Code, Claude Desktop, OpenClaw (compiled) plugins |
| **Direct model upsert** | `upsert_behavioral_model` | Agent-side LLM | OpenClaw (llm mode) |
| **External transcript observer (EDAMAME-driven)** | `upsert_behavioral_model_from_raw_sessions` (called from inside EDAMAME) | EDAMAME-side LLM | EDAMAME core periodic tick (`run_transcript_observer_tick`) |

Raw session ingest is preferred for production: the plugin sends transcript
text and metadata, and EDAMAME's configured LLM provider generates the
behavioral predictions internally. This eliminates per-cycle LLM cost on
the agent side.

The **external transcript observer** is the EDAMAME-side path that delivers
the internalization: it reads every **discovered** agent's transcript
directory directly and feeds the same ingest pipeline. "Discovered" means the
agent's transcript root is accessible on disk (e.g. `~/.cursor/projects/`,
`~/.claude/projects/`, `~/.codex/sessions/`, `~/.hermes/`); plugin install is
**not** required. That is distinct from **installed on the host**: the agent
product itself has a config or instruction footprint (for example
`~/.claude.json`) even if it has never written a transcript. The Agent
Inventory lists that as *Installed, not yet observed* until sessions appear;
*observed* means EDAMAME is ingesting transcripts (or receiving a plugin
push). Divergence detection works end-to-end for any agent the user
already has on their machine, once protection is on, even before they ever
click "Install plugin" in Config > Agents. When the EDAMAME plugin **is** installed in an agent's MCP
config, the plugin's own Node-side bridge also pushes behavioral models
in-process and the observer hash-skips when payloads match — so the two paths
are purely additive. Operators can pause, resume, or run-now the observer per
agent (installed or discovered) in the EDAMAME app's AI / Config tab. When the
observer is paused while the agent is discovered on disk, EDAMAME flags an
internal threat (`unsecured_<agent>`, one per agent type, including
`unsecured_codex`) on the next score cycle — the threat keys on discovery
(transcripts), not on product install and not on plugin install. An
installed-but-never-run agent is not unsecured.

### Observer vs plugin: the value boundary

The observer and the plugins are **not** peers. Keeping the directional
split explicit prevents two opposite mistakes: treating a plugin as the
security control, or dismissing a plugin as redundant.

| | EDAMAME host-side observer | Agent plugin (reasoning plane) |
|---|---|---|
| Role | **Security control of record** | **Cooperative enhancement** |
| Trust model | Observer-independent: it runs in the system plane, so a compromised agent cannot pause, blind, or silence it | Cooperative: the agent voluntarily declares intent; a plugin can only *add* signal, never *weaken* a verdict |
| Needs | The agent's transcripts readable on the host (agent **discovered** on disk) | The agent itself running the plugin's MCP bridge |
| Provides the guarantee? | **Yes** — divergence detection works with zero plugin installed | **No** — it adds coverage and convenience |

Why a plugin still earns its place, neither point being the guarantee
itself:

- **Off-host coverage.** When an agent runs where the host observer cannot
  read its transcripts — a remote box, SSH session, container, CI runner,
  VM, or a different user account — the in-process MCP bridge is the
  *only* path that delivers the behavioral model to EDAMAME. OpenClaw is
  the extreme case: it normally runs off-host (Lima/remote), so its plugin
  is usually the **primary** ingest path while the observer covers only the
  rarer host-resident deployment.
- **Cooperative onboarding and UX.** MCP-native discovery, pairing, the
  in-agent read-only posture/verdict surface, health checks, intent
  export, and security-awareness rules/skills — the turnkey ramp that gets
  a workstation monitored and lets the developer see verdicts from inside
  the agent.

In every mode the EDAMAME host stays the **verdict authority**: dismissing
findings, clearing divergence state, and any verdict-mutating capability
are operator-only on the EDAMAME side (the MCP observer-independence
policy). Plugins observe and onboard; they never adjudicate. This is also
why the `unsecured_<agent>` internal threat keys on **discovery**, not
plugin install — the security expectation is "this agent is being
observed", and the observer, not the plugin, is what satisfies it.

### Package Layout

The five workstation plugins (Cursor, Claude Code, Claude Desktop, Codex,
Hermes) share a common directory structure, while OpenClaw uses
`extensions/edamame/` and `skill/`:

```
bridge/                  Local stdio MCP bridge + forwarding
adapters/                Transcript parsing and payload assembly
service/                 Extrapolator, verdict reader, posture facade, health
setup/                   Install scripts, config templates, health check
  install.sh             Portable local install (bash)
  install.ps1            Portable local install (PowerShell, Windows)
docs/                    Architecture, setup, operator guidance
tests/                   Unit tests and E2E intent injection (e2e_inject_intent.sh)
```

Agent-specific additions:

| Plugin | Extra directories |
|--------|-------------------|
| Cursor | `.cursor-plugin/`, `rules/`, `skills/`, `agents/`, `commands/`, `assets/` |
| Claude Code | `.claude-plugin/`, `skills/`, `agents/`, `commands/`, `assets/` |
| Claude Desktop | `skills/`, `agents/`, `commands/` |
| OpenClaw | `extensions/edamame/` (MCP plugin), `skill/` (OpenClaw skill format) |

### Installation (retired 1.7.0)

In-app and CLI plugin install/provision was **retired in EDAMAME 1.7.0**.
Host-side transcript observation starts automatically when an agent's
transcripts are discovered on disk. Prevention is via **nono** / **srt**
governance harnesses (see Agents > Exposure > Host Blast Radius).

Level-2 plugin repos remain archived for reference; manual marketplace or
`setup/install.sh` installs are outside the EDAMAME product path.

Historical install commands (no longer in product):

```bash
# RETIRED -- do not use for new deployments
edamame-posture install-agent-plugin cursor
```

For operator-driven agent security, use the EDAMAME Security app (Agents tab,
AI / Config observer toggles) or `edamame_posture` daemon with host-side
observation enabled.

#### Marketplace (archived packages only)

| Plugin | Command |
|--------|---------|
| Cursor | Search "EDAMAME Security" in Cursor Marketplace |
| Claude Code | `/plugin marketplace add edamametechnologies/edamame_claude_code` |
| Claude Desktop | Archived package; EDAMAME app plugin install retired 1.7.0 |
| OpenClaw | `openclaw plugins enable edamame` (after manual copy) |

#### 3. Manual install from source

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

### Install Paths

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

### Pairing

Pairing authenticates the plugin with the EDAMAME MCP endpoint. The
credential is stored as `edamame-mcp.psk` in the plugin's state directory.

#### App-mediated pairing (macOS / Windows)

The EDAMAME Security app hosts the MCP server. Pairing uses an HTTP
handshake: the plugin posts a request, the user approves in the app, and
the credential is returned and stored automatically.

| Plugin | How to pair |
|--------|------------|
| Cursor | Call `edamame_cursor_control_center` MCP tool from within Cursor |
| Claude Code | Call `edamame_claude_code_control_center` MCP tool within Claude Code |
| Claude Desktop | Call `edamame_claude_desktop_control_center` MCP tool within Claude Desktop |
| OpenClaw | `bash setup/pair.sh` (from the [edamame_openclaw](https://github.com/edamametechnologies/edamame_openclaw) repo) |

#### Shared PSK (Linux / CLI / VM)

When `edamame_posture` is the MCP host, generate a PSK and start the MCP
endpoint:

```bash
edamame-posture mcp-generate-psk
edamame-posture mcp-start 3000 "<PSK>"
```

The `background-mcp-*` and `mcp-*` command forms are aliases — both work.

Write the PSK to the plugin's state directory or to `~/.edamame_psk`
(legacy shared path).

#### Credential lookup order

All four plugins resolve credentials in the same order:

1. `EDAMAME_MCP_PSK` environment variable
2. Plugin-specific `state/edamame-mcp.psk` file
3. `~/.edamame_psk` (legacy shared PSK, OpenClaw only)

### Uninstall (retired 1.7.0)

Product uninstall RPC/CLI was removed. Remove legacy plugin directories manually
if needed; see archived plugin repo docs.

### Scope Filters

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

### Provisioning Internals (retired 1.7.0)

Rust provisioning in `edamame_foundation` (`agent_plugin.rs`) remains for
legacy on-disk layouts but is no longer invoked from the app, posture CLI, or
RPC. Host-side observation uses `edamame_foundation::agent_transcripts` only.

### Behavioral Model Contract

| Property | Cursor | Claude Code | Claude Desktop | OpenClaw |
|----------|--------|-------------|----------------|----------|
| `agent_type` | `cursor` | `claude_code` | `claude_desktop` | `openclaw` |
| `agent_instance_id` | `<hostname>-<workspace_hash>` | `<hostname>-<workspace_hash>` | `<hostname>-<workspace_hash>` | Stable ID from `~/.edamame_openclaw_agent_instance_id` |
| Ingest API | `upsert_behavioral_model_from_raw_sessions` | `upsert_behavioral_model_from_raw_sessions` | `upsert_behavioral_model_from_raw_sessions` | `upsert_behavioral_model_from_raw_sessions` (compiled) or `upsert_behavioral_model` (llm) |
| Refresh trigger | MCP bridge lifecycle (periodic loop) | MCP bridge lifecycle (periodic loop) | MCP bridge lifecycle (periodic loop) | Cron job (1 min compiled, 5 min llm) |
| Transcript source | `~/.cursor/projects/.../agent-transcripts/` | `~/.claude/projects/` | `~/.claude/projects/` (Code-in-Desktop) + Cowork sessions (platform-specific) | OpenClaw session history API |

### E2E Testing

Two test suites validate each plugin:

| Suite | What it tests | Script |
|-------|--------------|--------|
| **Intent E2E** | Reasoning-plane pipeline: inject synthetic transcripts, verify behavioral predictions | `tests/e2e_inject_intent.sh` in each repo |
| **CVE / Divergence E2E** | System-plane detection: trigger attack simulations, verify EDAMAME detects them | `edamame_posture/tests/security/triggers/` (run with `--agent-type <plugin>`) |

Run intent tests:

```bash
cd edamame_cursor          && bash tests/e2e_inject_intent.sh
cd edamame_claude_code     && bash tests/e2e_inject_intent.sh
cd edamame_claude_desktop  && bash tests/e2e_inject_intent.sh
cd edamame_openclaw        && bash tests/e2e_inject_intent.sh
```

### Plugin Repositories

| Resource | Link |
|----------|------|
| EDAMAME for Cursor | [github.com/edamametechnologies/edamame_cursor](https://github.com/edamametechnologies/edamame_cursor) |
| EDAMAME for Claude Code | [github.com/edamametechnologies/edamame_claude_code](https://github.com/edamametechnologies/edamame_claude_code) |
| EDAMAME for Claude Desktop | [github.com/edamametechnologies/edamame_claude_desktop](https://github.com/edamametechnologies/edamame_claude_desktop) |
| EDAMAME for OpenClaw | [github.com/edamametechnologies/edamame_openclaw](https://github.com/edamametechnologies/edamame_openclaw) |
| EDAMAME Posture CLI | [github.com/edamametechnologies/edamame_posture](https://github.com/edamametechnologies/edamame_posture) |
| EDAMAME Core API (MCP reference) | [github.com/edamametechnologies/edamame_core_api](https://github.com/edamametechnologies/edamame_core_api) |
| Research paper (arXiv) | [github.com/edamametechnologies/agent_security](https://github.com/edamametechnologies/agent_security) |

## AI Assistant — User Guide

The **AI Assistant** (also called the "Agentic" system) is EDAMAME's own
agentic process: an intelligent automation feature that manages your security
posture by automatically analyzing and resolving security issues, network
alerts, and policy violations.

Unlike the [Agent Visibility](#agent-visibility-agent-detection--response)
capabilities above — which are deterministic and run without any model — the AI
Assistant **requires a configured LLM provider** (Cloud LLM, Claude, OpenAI, or
local Ollama). It is the one place where EDAMAME *uses* an LLM rather than
*watching* the agents that use one.

Think of it as your personal security analyst that:
- **Analyzes** security recommendations and network events
- **Decides** the best course of action based on context
- **Executes** or recommends actions automatically
- **Tracks** everything it does with full transparency

### Key Concepts

#### What is a "Todo"?

A **todo** is any actionable security recommendation on the Security radar:
- **Threats** — Security vulnerabilities that need remediation
- **Policy Violations** — Configuration issues to fix
- **Network Sessions** — Suspicious connections to review
- **Open Ports** — Exposed services to investigate
- **Pwned Breaches** — Data breach alerts to acknowledge

#### How the AI Helps

Instead of manually reviewing and acting on each todo, the AI Assistant:
1. **Understands context** — Reads the full details of each security issue
2. **Makes smart decisions** — Determines if action is safe and necessary
3. **Takes action** — Dismisses false positives, remediates threats, or escalates complex cases
4. **Explains reasoning** — Shows you why it made each decision

### Workflows

#### Turning protection on

Protection is off on a fresh install. Turn it on from the **protection
capsule** at the bottom-left of Security > Overview:

- **Connect Portal** (shown while no model is connected): accept the consent
  notice, sign in to the EDAMAME Portal in the browser, and protection turns
  on at once. "Sign in again" appears when a Portal session has expired.
- **Turn on protection**: starts the Assistant, attack pattern detection and
  intent divergence detection together, with or without a model. Detection
  then runs deterministically; a model adds its review and the Assistant's
  analysis. On desktop, protection also starts session capture and file
  monitoring.
- **Protected · 14:32:07** means protection is on and shows the time of the
  detectors' last check ("Stalled" when checks stop). Tap it to turn
  everything off; on desktop that also stops session capture and file
  monitoring.
- **Auto-fix** switches the Assistant from Review (it recommends, you confirm)
  to Auto (it fixes safe issues on its own). It is locked until protection is
  on and a tested model is connected, and asks for confirmation first.

To use your own model instead of the Portal (Claude, OpenAI or a local Ollama),
set it up in **Config > AI**, press **Test**, and turn protection on.

#### The Security radar

Security > Overview places every open todo (threats, policies, breaches,
devices, sessions, and the setup of LAN scan, breach and session monitoring)
on a radar by priority, in the sector of the section it belongs to, with the
**Next up** queue beside it. While protection is on, the HIGH and CRITICAL
findings of the two detectors join them. A todo shows the Assistant's verdict
(pending your confirmation, escalated, handled) only while the Assistant can
act -- protection on and a model connected; otherwise tap it to open its card
and fix it yourself.

#### Detections

**Security > Detections** (desktop) lists every attack-pattern and divergence
finding, low severity included. It does not depend on the model connection: a
finding the LLM reviewed and one the deterministic engine published sit side
by side, and connecting or disconnecting a model changes nothing here. Open a
finding for its evidence and, when a model reviewed it, the LLM's verdict and
reasoning; **Dismiss** creates a dismissal rule (a single finding, or a
broader scope, for a time or for good; a CRITICAL finding needs a rule that
may hide CRITICAL, with a reason), and **Restore** removes it. When you are
signed in to the Portal, a dismissal can also be reported to EDAMAME as a
false positive.

#### AI History

**Security > AI History** lists the Assistant's actions: fixes, dismissals,
escalations, pending suggestions and failures, with the reasoning of each.
It appears only while a model is connected (the EDAMAME Portal or your own).
**Confirm pending** runs the actions waiting for your approval and **Undo all**
reverts the Assistant's fixes; both ask first and say how many actions they
affect.

Disconnecting the model (signing out of the Portal, clearing your own model)
clears AI History: when you connect again, the Assistant starts fresh and
reviews your open todos again. The fixes it applied stay applied and can
still be undone from their own screens (a threat's rollback in Threats, the
dismissal rules, Network, Identity).

#### Decision Flow

Here's how the AI makes decisions:

```
Todo Received
    |
    v
AI Analyzes Context
    |
    v
AI Makes ONE of TWO Decisions:
    |
    +--> [Safe & Routine] -> "auto_resolve" decision
    |        |
    |        +--> [Auto level]   -> Execute Immediately -> Auto-Resolved
    |        +--> [Review level] -> Present for Review   -> Requires Confirmation
    |
    +--> [Complex / Risky] -> "escalate" decision -> Human Review Needed (Escalated)

If any step fails (LLM error, execution error, etc.) -> Failed (Retry Available)
```

**Important:** The AI only makes **two types of decisions**:
1. **"auto_resolve"** — The action is safe and routine
2. **"escalate"** — The action is complex or risky

The difference between **Auto-Resolved** and **Requires Confirmation** is
**the Assistant's level**, not what the AI decided:
- Same AI decision ("auto_resolve")
- The level determines execution:
  - **Auto** (Auto-fix on) → Executes automatically (Auto-Resolved)
  - **Review** → Waits for your approval (Requires Confirmation)

**Auto-Resolve Criteria (AI decides it's safe):**
- Low risk (e.g., dismissing false positives)
- Clear best practice (e.g., acknowledging old breaches)
- Well-established pattern (e.g., routine network cleanup)
- Risk score < 0.5 typically

**Escalation Criteria (AI decides it's risky):**
- High risk (e.g., critical system changes)
- Requires domain expertise
- Ambiguous situation
- Severity >= 5 for threats
- Risk score > 0.5 typically

### Technology and Providers

#### Large Language Models (LLMs)

The AI Assistant uses advanced language models to understand and reason about
security issues.

**Supported Providers:**

##### 1. Cloud LLM (EDAMAME)
- **Type:** Managed AI service hosted by EDAMAME
- **Best for:** Users who want hassle-free AI with flexible authentication options
- **Authentication:**
  - **OAuth** via [EDAMAME Portal](https://portal.edamame.tech) — sign in once, stay connected (GUI app)
  - **API Key** for headless / CLI environments — create keys in the Portal, set the `EDAMAME_LLM_API_KEY` env var
- **Cost:** Free and paying tiers available; see [portal.edamame.tech](https://portal.edamame.tech) for details
- **Features:**
  - Simple OAuth login for desktop apps
  - API keys available for CI/CD and server environments
  - Automatic model selection
  - Usage tracking displayed in the app
  - Subscription status and plan visible in AI Assistant settings
- **Availability:**
  - GUI app (EDAMAME Security) — uses OAuth authentication
  - CLI tools (edamame_posture) — uses API key authentication
- **Note:** When the subscription limit is reached, the app notifies you and prompts for a plan upgrade

##### 2. Claude (Anthropic)
- **Models:** Claude Sonnet 4.5, Claude Haiku 4.5
- **Best for:** Detailed reasoning, nuanced security decisions
- **Requires:** API key from console.anthropic.com
- **Cost:** Pay-per-use (most expensive but highest quality)

##### 3. OpenAI (GPT)
- **Models:** GPT-5, GPT-5 Mini
- **Best for:** Fast responses, general-purpose analysis
- **Requires:** API key from platform.openai.com
- **Cost:** Pay-per-use (medium cost, good quality)

##### 4. Ollama (Local)
- **Models:** Any model you run locally (llama3, mistral, etc.)
- **Best for:** Privacy-conscious users, no internet dependency
- **Requires:** Ollama installed locally, custom base URL
- **Cost:** Free (runs on your hardware)

#### Model Context Protocol (MCP) integration

**What is MCP?**
MCP is a protocol that lets LLMs securely access external tools and data. In
EDAMAME Security:

- The **MCP Server** runs locally on your machine
- An **LLM** connects to it over a secure channel (dual-mode authentication)
- The **tools** exposed to the LLM include everything the app does: system remediations, network and traffic scanning, identity management, and agentic automation

**Dual-mode authentication:**
1. **Per-client credentials** (app-mediated pairing): Desktop clients POST to `/mcp/pair`, the user approves in the app, and the client receives an `edm_mcp_...` credential. No PSK copy / paste needed.
2. **Shared PSK** (CLI / headless): Bearer token for CLI tools, provisioning scripts, and automation.

The auth middleware accepts both credential types in the Bearer token header.
For first-class agent integrations built on top of MCP (Cursor, Claude Code,
Claude Desktop, OpenClaw, Codex, Hermes), see [Agent Plugins](#agent-plugins).

#### Privacy & Security

**Your data:**
- Todo data is sent to the LLM for analysis (encrypted in transit)
- Context is sanitized before being sent to the LLM (see `edamame_foundation` for the open-source code used)
- You control what the AI can do (undo capability on all actions)
- All actions are logged and transparent

**With Ollama (local LLM):**
- **Zero cloud dependency:** everything runs locally
- **Complete privacy:** no data leaves your machine
- **Full control:** you manage the model and its behavior

**Best Practices:**
- Start at the Review level to learn the AI's behavior
- Review AI History regularly
- Use undo if the AI makes a mistake
- Report issues to improve the system

### Configuration

#### Setting Up Your AI Provider

##### Option A: Cloud LLM (EDAMAME) — Recommended for Most Users

1. **Open AI Assistant Settings**
   - Go to **Config > AI** in the app

2. **Sign In to Cloud LLM**
   - Click "Sign in to Cloud LLM"
   - You'll be redirected to EDAMAME Portal for OAuth authentication
   - Sign in with your EDAMAME account (or create one)

3. **Automatic Configuration**
   - Once signed in, the AI is ready to use immediately
   - Your subscription plan and usage are displayed in the settings

4. **Subscription**
   - Free and paying tiers available
   - See [portal.edamame.tech](https://portal.edamame.tech) for pricing and plan details

5. **API Keys for Headless Environments** (Optional)
   - Go to [portal.edamame.tech](https://portal.edamame.tech) and navigate to API Keys
   - Create a new API key with a descriptive name
   - Use with `--agentic-provider edamame` and set the `EDAMAME_LLM_API_KEY` environment variable

**Note:** Cloud LLM supports both OAuth (GUI app) and API keys (CLI / headless). For third-party LLMs in CLI, use Claude, OpenAI, or Ollama with their respective API keys.

##### Option B: Bring Your Own LLM (Claude, OpenAI, Ollama)

1. **Open Settings**
   - Go to **Config > AI** (the capsule's AI part opens it once a model is connected)

2. **Choose Provider**
   - Select Claude, OpenAI, or Ollama

3. **Enter Credentials**
   - **Claude / OpenAI:** Enter API key
   - **Ollama:** Enter base URL (e.g., `http://localhost:11434`)

4. **Select Model**
   - Choose from available models for your provider

5. **Test Connection**
   - Click "Test Connection" to verify setup
   - You should see a success message

6. **Save & Close**
   - Configuration is automatically saved on a successful test

**Note:** Selecting your own LLM automatically signs you out of Cloud LLM (and vice versa).

#### MCP Server Setup (Optional — For Advanced Users)

**What is MCP?**
MCP (Model Context Protocol) allows external AI tools like Claude Desktop to
connect to EDAMAME and control it securely. Think of it as an API for AI
assistants.

**When to use it:**
- You want to use Claude Desktop to manage your security
- You're building automation workflows (n8n, Zapier)
- You want to test the AI features programmatically

**Authentication modes:**
- **Per-client credentials** (desktop apps): Client POSTs to `/mcp/pair`, user approves in the app, client receives an `edm_mcp_...` credential. No PSK copy / paste.
- **Shared PSK** (CLI / headless): Bearer token for CLI tools, provisioning scripts, and automation.

**Setup:**

1. **Open MCP Dialog**
   - Click the hub icon next to AI settings

2. **Choose authentication**
   - **Pairing (desktop clients):** Client initiates pairing; approve in the app. Use the pairing RPC methods: `mcpApprovePairing`, `mcpRejectPairing`, `mcpListPairedClients`, `mcpGetPendingPairingRequests`, `mcpRevokePairedClient`, `mcpRotatePairedClient`.
   - **Shared PSK (CLI / headless):** Click "Generate PSK" to create a secure key; copy and save it securely (you'll need this for clients).

3. **Configure Port**
   - Default: 3000 (change if the port is in use)
   - The server only binds to localhost (127.0.0.1) for security

4. **Start Server**
   - Click "Enable MCP Server"
   - The server runs in the background on port 3000
   - Status shows: "Running on port 3000"

5. **Connect External Clients**
   - **Claude Desktop:** Add to configuration (see below)
   - **MCP Inspector:** Test interactively (see the testing section)
   - **Custom clients:** Use the MCP protocol (pairing or PSK)

**Claude Desktop Integration:**

Add to `~/Library/Application Support/Claude/claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "edamame": {
      "command": "npx",
      "args": [
        "mcp-remote",
        "http://127.0.0.1:3000/mcp",
        "--header",
        "Authorization: Bearer YOUR_PSK_OR_CLIENT_CREDENTIAL_HERE"
      ]
    }
  }
}
```

Replace `YOUR_PSK_OR_CLIENT_CREDENTIAL_HERE` with either: (a) your PSK from the Generate PSK step, or (b) the `edm_mcp_...` credential obtained via pairing.

**Now Claude Desktop can:**
- Check your security score
- List and analyze your todos
- Process todos automatically with AI reasoning
- Undo actions if needed

**Example Claude conversation:**
```
You: "Check my security posture and fix anything safe"
Claude: *uses EDAMAME MCP tools*
       "I found 12 security items. Fixed 8 routine issues,
        need your review on 2 complex ones..."
```

#### Testing Your MCP Server

**MCP Inspector** is a free interactive tool to test and debug MCP servers.

**Quick Test (5 minutes):**

**Step 1: Ensure the MCP Server is Running**
- Open the EDAMAME app → AI Assistant settings
- Verify "MCP Server: Running on port 3000"
- Have your credential ready: either a paired client credential (`edm_mcp_...`) or a shared PSK

**Step 2: Launch Inspector**

```bash
npx @modelcontextprotocol/inspector \
  --server-url http://127.0.0.1:3000/mcp \
  --transport http
```

**Step 3: Configure Authentication in the Inspector UI**

When Inspector opens in your browser:
1. Click "Custom Headers"
2. Add header name: `Authorization`
3. Add header value: `Bearer YOUR_CREDENTIAL_HERE`

Replace `YOUR_CREDENTIAL_HERE` with either your paired client credential (`edm_mcp_...`) or your shared PSK.

**Step 4: Test in the Browser**

Inspector opens at `http://localhost:5173` and shows:
- Connection: "Connected" (green)
- Tools: the tool list (advisor, score, agentic, observation, identity, LAN)
- Interactive: Click any tool → Enter params → See results

**What to try:**

1. **Get Security Score**
   - Click `score_get`
   - Params: `{"complete_only": false}`
   - See your current security score

2. **List Todos**
   - Click `advisor_get_todos`
   - Params: `{}` (empty)
   - See all pending security items

3. **Process Todos with AI**
   - Click `agentic_process_todos`
   - Params: `{"confirmation_level": "manual"}`
   - See AI decisions for each todo

4. **View Action History**
   - Click `advisor_get_action_history`
   - Params: `{"limit": 10}`
   - See recent AI actions

**Troubleshooting:**

- **Connection failed?**
  - Verify the server is running in the EDAMAME app
  - Use `127.0.0.1`, not `localhost`, in the URL
  - Test: `curl http://127.0.0.1:3000/health` (should return "OK")

- **401 Unauthorized?**
  - Check the credential is correct (paired `edm_mcp_...` or shared PSK; copy fresh from the app if needed)
  - Verify format: `Authorization: Bearer <credential>` (note the space after "Bearer")

- **No tools showing?**
  - Wait 2-3 seconds after connection
  - Refresh the browser page (F5)

### Tips & Best Practices

#### Learning Phase
1. Keep the Assistant at **Review** (Auto-fix off)
2. Review AI reasoning for each decision
3. Understand patterns before turning Auto-fix on
4. Use the "View Details" button to see full context

#### Production Use
1. Turn **Auto-fix** on for daily maintenance
2. Review AI History regularly (weekly)
3. Investigate escalated items promptly

#### Security Hardening
1. Use **Ollama locally** for maximum privacy
2. Enable the MCP server only when needed
3. Use per-client pairing for desktop clients, or a strong shared PSK for CLI / headless MCP authentication
4. Monitor failed actions for potential issues

#### Troubleshooting
1. **AI not responding?** Check the API key and test the connection again
2. **Wrong decisions?** Use undo and provide feedback
3. **Failed actions?** Check network connectivity and retry

### FAQ

**Q: What's the difference between Review and Auto (Auto-fix)?**
A: The AI makes the same decisions at both levels. The difference is execution:
- **Auto (Auto-fix on):** the Assistant executes safe actions immediately (you see "Auto-Resolved")
- **Review:** it shows you what it would do and waits for your approval (you see "Requires Confirmation")

At both levels, risky / complex actions are escalated for manual review. Stay at Review to learn what the AI considers safe before turning Auto-fix on.

**Q: What happens to AI History when I disconnect the model?**
A: It is cleared, and a reconnection starts fresh: the Assistant reviews your open todos again. The fixes it applied stay applied and can still be undone from their own screens. Detections (the detectors' findings) is not affected by the model connection.

**Q: How much does it cost?**
A: Depends on your provider:
- Cloud LLM (EDAMAME): Free and paying tiers; see [portal.edamame.tech](https://portal.edamame.tech) for details
- Claude / OpenAI: pay-per-use (you pay Anthropic / OpenAI directly)
- Ollama: Free (runs locally on your hardware)

**Q: Can I use it offline?**
A: Yes, with Ollama. Configure it to run locally and the AI works without internet. (The deterministic visibility and detection features described above already work offline with no provider at all.)

**Q: What happens if I disagree with the AI?**
A: Click "Undo" on any action.

**Q: Is my data private?**
A: All data is sanitized before being sent to any LLM (see `edamame_foundation` for the open-source code used):
- **Cloud LLM (EDAMAME):** Sanitized context is sent to EDAMAME's secure backend (encrypted in transit and at rest)
- **Claude / OpenAI:** Sanitized context is sent directly to their APIs (encrypted in transit)
- **Ollama:** Everything stays local on your machine — maximum privacy

**Q: Can I customize AI behavior?**
A: Keep the Assistant at Review for full control; Config > AI also sets how often it runs and how the detectors use the model (adjudication).

**Q: How do I know the AI made the right decision?**
A: Every action includes full reasoning in AI History. Click "View Details" to see the AI's thought process.

### Getting Started Checklist

- [ ] Configure an AI provider:
  - **GUI App:** Sign in to Cloud LLM (EDAMAME) via OAuth — simple and secure
  - **CLI / Headless:** Create an API key at [portal.edamame.tech](https://portal.edamame.tech)
  - **Alternative:** Set up Claude, OpenAI, or Ollama with your own credentials
- [ ] Test the connection successfully (own model) or sign in (Portal)
- [ ] Turn protection on from the capsule under the Security radar
- [ ] Keep the Assistant at Review first
- [ ] Review 5-10 AI decisions in AI History to understand the reasoning
- [ ] Turn Auto-fix on when comfortable

## Repository purpose

This repository serves as the public issue tracker for EDAMAME Security. The application itself is **closed source**; we use this space to:

- Track bug reports and feature requests
- Engage with the community
- Share updates and announcements
- Collect feedback from users

## Getting started

To download EDAMAME Security, see [edamame.tech](https://www.edamame.tech).

## Documentation

| Document | Content |
|----------|---------|
| [AI Assistant — User Guide](#ai-assistant--user-guide) | AI Assistant user guide -- workflows, MCP testing, LLM providers (merged into this README) |
| [Agent Plugins](#agent-plugins) | Agent plugin architecture -- Cursor, Claude Code, Claude Desktop, OpenClaw, Codex, Hermes repos, install paths, pairing, scope filters, E2E testing (merged into this README) |
| [Troubleshooting](#troubleshooting) | Feedback button behavior, where to find app/helper logs and crash files on macOS, Windows, and Linux, and a one-command log collector to email support |
| [Feature Wiki](https://github.com/edamametechnologies/edamame_security/wiki) | Full feature descriptions with screenshots |
| [EDAMAME Core API](https://github.com/edamametechnologies/edamame_core_api) | Public API and MCP tool reference |
| [EDAMAME Posture CLI](https://github.com/edamametechnologies/edamame_posture) | CLI for security posture, CI/CD policy enforcement, and plugin provisioning |

## Troubleshooting

### Reporting a problem with the Feedback button

The quickest way to send a problem report with diagnostics attached is
the **Feedback** button ("Send feedback or report an issue") in the support
dock. It opens a consent dialog where you enter a short
description (required) and your email (required) after reviewing the
feedback privacy notice.

On submit, EDAMAME bundles the following into the report sent to its
backend:

- Your description and email address.
- App version, operating system and version, and EDAMAME Helper state.
- The active threat model name, date, and signature, plus your current
  Security Score.
- A recent slice of the **app log** (up to the last 100 lines).
- A recent slice of the **EDAMAME Helper log** (up to the last 100
  lines) -- included only on macOS/Windows/Linux when the helper is
  installed and enabled. On iOS and Android the helper log is empty
  because there is no helper on those platforms.

This is the recommended way to share logs: on macOS and on mobile the
app log is kept only in memory and is never written to a file you can
open yourself, so the Feedback button is the only way to retrieve it.
What the report contains and how it is used is described in the privacy
notice shown inside the dialog.

### Finding the logs manually

To inspect logs locally -- for example to attach them to a GitHub issue
-- use the locations below. EDAMAME has two logging components:

- **App** -- the EDAMAME Security user interface.
- **EDAMAME Helper** -- the privileged background service/daemon that
  runs system checks, packet capture, and remediations. On Linux this
  functionality is built into the `edamame_posture` daemon.

**Rolling log files** are named `<basename>_<pid>.YYYY-MM-DD` (note: **no
`.log` extension**), rotate daily, and keep the last 7 days. The
`<basename>` is `edamame_helper`, `edamame_posture`, `edamame` (the app),
or `edamame_cli`.

**Crash / panic files.** Whenever a component panics it also writes a
one-shot `<type>_panic_<unix-timestamp>.txt` file containing the panic
message, source location, full backtrace, and environment info. The
`<type>` prefix is the short component name and is **not** the same as the
rolling-log basename: look for `helper_panic_*.txt`, `posture_panic_*.txt`,
`app_panic_*.txt`, or `cli_panic_*.txt`. Three things to know:

- Panic files are written **even for components that keep no rolling log
  file** (for example the macOS/Linux app), so they are often the only
  on-disk evidence of a GUI crash.
- A panic file can land in a **different directory than the rolling logs**:
  the Helper and Posture daemons on macOS/Linux write panic files into
  `/var/log/edamame/`; in **every other case** (the app on any OS, and the
  Helper on Windows) the panic file is written **next to that component's
  executable**.
- Several panic files with timestamps a few seconds apart mean the
  component crash-looped and was restarted repeatedly by the OS service
  manager. Attach the most recent one to a GitHub issue, or send it with
  the Feedback button.

#### macOS

| Component | Rolling logs | Crash / panic file |
| --- | --- | --- |
| EDAMAME Helper | `/var/log/edamame/edamame_helper_<pid>.YYYY-MM-DD` (owned by `root` -- read with `sudo`) | `/var/log/edamame/helper_panic_<timestamp>.txt` (also `root`) |
| App | Not written to a file -- use the in-app **Feedback** button (it also captures the in-memory app log) | `app_panic_<timestamp>.txt` next to the app binary inside `EDAMAME Security.app/Contents/MacOS/`; may be absent if the sandboxed bundle is not writable, in which case rely on Feedback |

```bash
# Tail the most recent helper log
sudo tail -100 "$(sudo ls -t /var/log/edamame/edamame_helper_* | head -1)"

# List any crash / panic artifacts (helper or posture)
sudo ls -lt /var/log/edamame/*_panic_*.txt 2>/dev/null
```

#### Windows

| Component | Rolling logs | Crash / panic file |
| --- | --- | --- |
| App | `%APPDATA%\com.edamametech\EDAMAME Security\` (expands to `C:\Users\<you>\AppData\Roaming\com.edamametech\EDAMAME Security\`) | `app_panic_<timestamp>.txt` next to the app executable (the install directory), **not** in `%APPDATA%` |
| EDAMAME Helper | Next to the helper executable -- default `C:\Program Files\edamame_helper\bin\` | `helper_panic_<timestamp>.txt` in that same `bin\` folder |

```powershell
# App logs (the edamame_<pid>.YYYY-MM-DD files; the .json files are app state)
Get-ChildItem "$env:APPDATA\com.edamametech\EDAMAME Security" | Sort-Object LastWriteTime

# Helper logs and any crash / panic artifacts
Get-ChildItem "C:\Program Files\edamame_helper\bin\edamame_helper_*"
Get-ChildItem "C:\Program Files\edamame_helper\bin\*_panic_*.txt"
```

#### Linux

On Linux the privileged component is the `edamame_posture` daemon (the
GUI is a thin client that talks to it). Where its rolling logs go depends
on how it was started, but the **daemon's panic files always go to
`/var/log/edamame/`** (`posture_panic_<timestamp>.txt`, or
`helper_panic_<timestamp>.txt` if the separate helper daemon is in use):

| How it runs | Rolling logs | Crash / panic file |
| --- | --- | --- |
| systemd service (default for the `.deb` package and the GUI app) | `sudo journalctl -u edamame_posture` | `/var/log/edamame/posture_panic_<timestamp>.txt` |
| `edamame_posture background-start` | `/var/log/edamame/edamame_posture_<pid>.YYYY-MM-DD` | `/var/log/edamame/posture_panic_<timestamp>.txt` |

```bash
# systemd service logs (most installs)
sudo journalctl -u edamame_posture --since "1 hour ago" --no-pager

# background-start daemon logs
sudo tail -100 "$(sudo ls -t /var/log/edamame/edamame_posture_* | head -1)"

# List any crash / panic artifacts
sudo ls -lt /var/log/edamame/*_panic_*.txt 2>/dev/null
```

### Collecting logs for support (one command)

To send diagnostics to **support@edamame.tech**, paste the one-liner for
your platform into a terminal. Each command gathers the most recent helper
and app logs plus any crash / panic files into a single timestamped
`edamame-logs-*.zip` (rolling logs are size-capped so the archive stays
small enough to email), then prints the path. Attach that zip to an email
to support@edamame.tech.

> On macOS the app's own log is kept in memory and is never written to a
> file, so the zip captures the helper log only; use the in-app **Feedback**
> button to include the app log. On Windows and Linux the app/daemon logs
> are on disk and are captured by the command.

**macOS** (Terminal -- prompts once for your admin password to read the helper log):

```bash
D=$(mktemp -d); H=$(sudo find /var/log/edamame -maxdepth 1 -name 'edamame_helper_*' -exec ls -t {} + 2>/dev/null | head -1); [ -n "$H" ] && sudo tail -c 20000000 "$H" > "$D/$(basename "$H")"; sudo find /var/log/edamame -maxdepth 1 -name '*_panic_*.txt' -exec cp {} "$D/" \; 2>/dev/null; sudo chown -R "$(id -un)" "$D" 2>/dev/null; Z="$HOME/Desktop/edamame-logs-$(date +%Y%m%d-%H%M%S).zip"; (cd "$D" && zip -qr "$Z" .) && echo "Created $Z -- email it to support@edamame.tech"; rm -rf "$D"
```

**Windows** (PowerShell):

```powershell
$d=Join-Path $env:TEMP 'edamame-logs'; Remove-Item $d -Recurse -Force -ErrorAction SilentlyContinue; New-Item $d -ItemType Directory -Force | Out-Null; $app=Join-Path $env:APPDATA 'com.edamametech\EDAMAME Security'; $hb='C:\Program Files\edamame_helper\bin'; Get-ChildItem "$hb\edamame_helper_*","$app\edamame_*" -ErrorAction SilentlyContinue | Where-Object { $_.Name -match '\.\d{4}-\d{2}-\d{2}$' } | Sort-Object LastWriteTime | Select-Object -Last 5 | Copy-Item -Destination $d -ErrorAction SilentlyContinue; Get-ChildItem "$hb\*_panic_*.txt","$app\*_panic_*.txt" -ErrorAction SilentlyContinue | Copy-Item -Destination $d -ErrorAction SilentlyContinue; $z=Join-Path $env:USERPROFILE "Desktop\edamame-logs-$(Get-Date -Format yyyyMMdd-HHmmss).zip"; Compress-Archive "$d\*" $z -Force; "Created $z -- email it to support@edamame.tech"
```

**Linux** (Terminal -- captures the `edamame_posture` daemon log, which serves both the app and helper roles):

```bash
D=$(mktemp -d); sudo journalctl -u edamame_posture --since "1 day ago" --no-pager 2>/dev/null | tail -c 20000000 > "$D/edamame_posture_journal.log"; L=$(sudo find /var/log/edamame -maxdepth 1 \( -name 'edamame_posture_*' -o -name 'edamame_helper_*' \) -exec ls -t {} + 2>/dev/null | head -1); [ -n "$L" ] && sudo tail -c 20000000 "$L" > "$D/$(basename "$L")"; sudo find /var/log/edamame -maxdepth 1 -name '*_panic_*.txt' -exec cp {} "$D/" \; 2>/dev/null; sudo chown -R "$(id -un)" "$D" 2>/dev/null; Z="$HOME/edamame-logs-$(date +%Y%m%d-%H%M%S).zip"; (cd "$D" && zip -qr "$Z" .) && echo "Created $Z -- email it to support@edamame.tech"; rm -rf "$D"
```

## Support and Issues

If you encounter any issues or have feature requests, please:

1. Check existing [issues](https://github.com/edamametechnologies/edamame_security/issues) to see if your problem has already been reported
2. If not, [create a new issue](https://github.com/edamametechnologies/edamame_security/issues/new) with detailed information about:
   - Your operating system and version
   - Steps to reproduce the issue
   - Expected vs actual behavior
   - Any error messages or screenshots
   - Relevant logs (use the in-app Feedback button, or see [Troubleshooting](#troubleshooting) for where to find them manually)
