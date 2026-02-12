# EDAMAME Security: Free App

> Part of the **[EDAMAME Agents](https://github.com/edamametechnologies#edamame-agents)** family - AI-powered security assistants for the modern SDLC with shared LLM subscription via [EDAMAME Portal](https://portal.edamame.tech).

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
  - PSK authentication for external AI tools
  - 9 security automation tools (advisor, score, agentic)
  - Connect Claude Desktop, MCP Inspector, or build custom workflows
  - Test interactively with MCP Inspector: `npx @modelcontextprotocol/inspector --server-url http://127.0.0.1:3000/mcp --transport http`
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
- Capture traffic sessions with domain and process context
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

#### Chocolatey Installation (Recommended)
The easiest way to install on Windows:

```powershell
# Install EDAMAME Security
choco install edamame

# Install EDAMAME Helper (required for full system access)
choco install edamame-helper

# Install Npcap (required for traffic capture)
choco install npcap
```

To update to the latest versions:
```powershell
choco upgrade edamame
choco upgrade edamame-helper
choco upgrade npcap
```

**Note**: All three packages are recommended for full functionality:
- **edamame**: Main application with UI
- **edamame-helper**: Enables privileged security operations
- **npcap**: Enables network traffic capture and monitoring

#### Microsoft Store installation

Step 1: Install and Open the app from Microsoft Store

- Download from the [Microsoft Store](https://www.microsoft.com/store/apps/9N399LMTKQLQ) for a Microsoft-vetted sandboxed app
<img width="711" height="634" alt="Screenshot 2025-12-08 at 5 17 43 PM" src="https://github.com/user-attachments/assets/dd6ccc1d-5959-46cc-99c8-89b724fff014" />
<br>
Step 2: Install EDAMAME Helper from Todo action(s)
In the advisor Tab of the app click on this Todo action item for the Helper software…
<img width="717" height="146" alt="Screenshot 2025-12-08 at 5 19 19 PM" src="https://github.com/user-attachments/assets/3db8d298-3cf7-4e7c-b452-18cb6ccedb49" />

…and click on “Push to installˮ.
<br><br/>
<img width="724" height="431" alt="Screenshot 2025-12-08 at 5 20 06 PM" src="https://github.com/user-attachments/assets/c2b23276-1ff4-44d0-b1a6-1ed836e4cc04" />
<br><br/>
This Helper is needed due to the limitations of Apps installed from the Microsoft Store.

If you prefer you can download directly the EDAMAME Helper Binary
[EDAMAME Helper](https://github.com/edamametechnologies/edamame_helper/releases) for system access

After the binary is downloaded run the downloaded install package in “Downloadsˮ.

Click on “More infoˮ then “Run anywayˮ to allow the install.

<img width="614" height="575" alt="Screenshot 2025-12-08 at 5 22 40 PM" src="https://github.com/user-attachments/assets/aeb0d067-463e-4a67-84cc-7232cf0ae153" />

Step 4 (Optional): Install ncap
Install npcap to enable traffic capture
[Npcap](https://npcap.com/#download) for traffic capture

#### Direct Download
1. Download the installer: [edamame-latest.msix](https://edamame.s3.eu-west-1.amazonaws.com/windows/edamame-latest.msix)
2. Install the [EDAMAME Helper](https://github.com/edamametechnologies/edamame_helper/releases)
3. Install [Npcap](https://npcap.com/#download) to enable traffic capture

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

## Feature Wiki

- Full feature descriptions with screenshots are available in the project wiki: [github.com/edamametechnologies/edamame_security/wiki](https://github.com/edamametechnologies/edamame_security/wiki)

## Support and Issues

If you encounter any issues or have feature requests, please:

1. Check existing [issues](../../issues) to see if your problem has already been reported
2. If not, [create a new issue](../../issues/new) with detailed information about:
   - Your operating system and version
   - Steps to reproduce the issue
   - Expected vs actual behavior
   - Any error messages or screenshots
