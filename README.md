# EDAMAME Security

> **EDAMAME** is the developer-first, agent-first runtime security layer for the SDLC. **EDAMAME Security** protects workstations and local coding sessions, **EDAMAME Posture** secures CI/CD runners, build hosts, and self-hosted agent hosts, **EDAMAME Hub** gives teams fleet visibility and proof, and **EDAMAME Portal** handles account access and managed LLM subscription.

## Overview

EDAMAME Security is your all‑in‑one tool to secure, understand, and prove the security of your development workstation—from OS to network.

**Note: This application is currently closed source. This repository is used for issue tracking and community feedback.**

## Key Features

### Security Advisor for System and Network Issues
- Holistic security posture report using frontier LLM
- At‑a‑glance view of outstanding issues
- Sort issues by priority and category
- Be notified of new issues in real-time

### AI Assistant (Agentic System)
- Intelligent automation that analyzes and resolves security issues automatically
- Two operational modes:
  - **"Do It For Me"** - Fully automatic handling of routine security tasks
  - **"Analyze & Recommend"** - Review AI decisions before execution
- Scheduled automation with granular control:
  - **"Auto run"** toggle - Schedule automatic processing at regular intervals (5min/1h/1day)
  - **"Auto confirm"** toggle - Control whether scheduled runs execute safe actions immediately or wait for approval
- Collapsible automation panel with live workflow status updates, Do It For Me / Analyze & Recommend buttons, and an inline cancel action for in-flight jobs.
- Supports multiple LLM providers:
  - **Cloud LLM (EDAMAME)** - Managed AI service with OAuth authentication via EDAMAME Portal; free and paying tiers (see [portal.edamame.tech](https://portal.edamame.tech)); optional API keys for headless environments
  - **Claude (Anthropic)** - Detailed reasoning and nuanced security decisions (API key required)
  - **OpenAI (GPT)** - Fast responses and general-purpose analysis (API key required)
  - **Ollama (Local)** - Privacy-focused, runs entirely on your machine (no cloud dependency)
- Complete transparency with filterable action history, Confirm/Undo All controls, detailed reasoning per action, and deep links to related security views.
- Undo capability for all automated actions
- **Model Context Protocol (MCP) integration**:
  - Secure localhost-only server (port 3000) with Streamable HTTP transport (exposed on desktop builds; mobile hides the control)
  - Dual-mode authentication: per-client credentials via app-mediated pairing (desktop clients POST to `/mcp/pair`, user approves in app, client gets `edm_mcp_...` credential) or shared PSK for CLI/headless tools and automation
  - 19 tools across 5 categories: advisor, observation (sessions with L7 process attribution, LAN devices, breaches, score), identity management (add/remove/list monitored emails), LAN configuration, and agentic automation
  - Sessions include deep L7 enrichment: process lineage, parent chain, open files (sensitive file tracking), temp-origin detection, resource usage
  - Dynamic identity management: add/remove emails for HIBP breach monitoring at runtime
  - First-class agent integrations for runtime behavioral monitoring -- see [PLUGINS.md](PLUGINS.md) for architecture, install paths, pairing, and E2E testing:
    - [EDAMAME for Cursor](https://github.com/edamametechnologies/edamame_cursor) -- Cursor IDE plugin (Cursor Marketplace)
    - [EDAMAME for Claude Code](https://github.com/edamametechnologies/edamame_claude_code) -- Claude Code plugin (Claude Code Marketplace)
    - [EDAMAME for Claude Desktop](https://github.com/edamametechnologies/edamame_claude_desktop) -- Claude Desktop plugin (Code-in-Desktop and Cowork modes)
    - [EDAMAME for OpenClaw](https://github.com/edamametechnologies/edamame_openclaw) -- OpenClaw agent plugin
    - [EDAMAME for Codex CLI](https://github.com/edamametechnologies/edamame_codex) -- OpenAI Codex CLI plugin
    - [EDAMAME for Hermes](https://github.com/edamametechnologies/edamame_hermes) -- Nous Research Hermes Agent plugin
  - Connect MCP Inspector or build custom workflows
  - Test interactively with MCP Inspector: `npx @modelcontextprotocol/inspector --server-url http://127.0.0.1:3000/mcp --transport http`
  - See [EDAMAME Core API MCP Reference](https://github.com/edamametechnologies/edamame_core_api/blob/main/MCP.md) for complete tool documentation
- Interactive features: email reports, custom security questions once you open the latest report dialog
- See [AGENTIC.md](AGENTIC.md) for detailed user guide and MCP testing instructions

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
# Add the EDAMAME tap
brew tap edamametechnologies/tap

# Install EDAMAME Security
brew install --cask edamame

# Install EDAMAME Helper (required for full system access)
brew install --cask edamame-helper
```

To update to the latest versions:
```bash
brew upgrade --cask edamame
brew upgrade --cask edamame-helper
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
alongside the app. The easiest path is to let the app prompt you: in the
**Advisor** tab, click the Todo action item for the Helper software and click
"Push to install".
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
| [AGENTIC.md](AGENTIC.md) | AI Assistant user guide -- workflows, MCP testing, LLM providers |
| [PLUGINS.md](PLUGINS.md) | Agent plugin architecture -- Cursor, Claude Code, Claude Desktop, OpenClaw, Codex, Hermes repos, install paths, pairing, scope filters, E2E testing |
| [Troubleshooting](#troubleshooting) | Feedback button behavior and where to find app/helper logs on macOS, Windows, and Linux |
| [Feature Wiki](https://github.com/edamametechnologies/edamame_security/wiki) | Full feature descriptions with screenshots |
| [EDAMAME Core API](https://github.com/edamametechnologies/edamame_core_api) | Public API and MCP tool reference |
| [EDAMAME Posture CLI](https://github.com/edamametechnologies/edamame_posture) | CLI for security posture, CI/CD policy enforcement, and plugin provisioning |

## Troubleshooting

### Reporting a problem with the Feedback button

The quickest way to send a problem report with diagnostics attached is
the **Feedback** button ("Send feedback or report an issue") in the
**Advisor** tab. It opens a consent dialog where you enter a short
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

Where logs are written to files, the files are named
`<component>_<pid>.YYYY-MM-DD` (note: **no `.log` extension**) and rotate
daily. If a component crashes, a `<component>_panic_<timestamp>.txt` file
is written alongside the logs.

#### macOS

| Component | Where to look |
| --- | --- |
| EDAMAME Helper | `/var/log/edamame/edamame_helper_<pid>.YYYY-MM-DD` (owned by `root` -- read with `sudo`) |
| App | Not written to a file. Use the in-app **Feedback** button to capture and send the app log. |

```bash
# Tail the most recent helper log
sudo tail -100 "$(sudo ls -t /var/log/edamame/edamame_helper_* | head -1)"
```

#### Windows

| Component | Where to look |
| --- | --- |
| App | `%APPDATA%\com.edamametech\EDAMAME Security\` (expands to `C:\Users\<you>\AppData\Roaming\com.edamametech\EDAMAME Security\`) |
| EDAMAME Helper | Next to the helper executable -- default `C:\Program Files\edamame_helper\bin\` |

```powershell
# App logs (the edamame_<pid>.YYYY-MM-DD files; the .json files are app state)
Get-ChildItem "$env:APPDATA\com.edamametech\EDAMAME Security" | Sort-Object LastWriteTime

# Helper logs
Get-ChildItem "C:\Program Files\edamame_helper\bin\edamame_helper_*"
```

#### Linux

On Linux the privileged component is the `edamame_posture` daemon (the
GUI is a thin client that talks to it). Where its logs go depends on how
it was started:

| How it runs | Where to look |
| --- | --- |
| systemd service (default for the `.deb` package and the GUI app) | `sudo journalctl -u edamame_posture` |
| `edamame_posture background-start` | `/var/log/edamame/edamame_posture_<pid>.YYYY-MM-DD` |

```bash
# systemd service logs (most installs)
sudo journalctl -u edamame_posture --since "1 hour ago" --no-pager

# background-start daemon logs
sudo tail -100 "$(sudo ls -t /var/log/edamame/edamame_posture_* | head -1)"
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
