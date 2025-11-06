# EDAMAME Security: Free App

## Overview

EDAMAME Security is your all‑in‑one tool to secure, understand, and prove the security of your development workstation—from OS to network.

**⚠️ Note: This application is currently closed source. This repository is used for issue tracking and community feedback.**

## Key Features

### 🛡️ Security Advisor for System and Network Issues
- Holistic security posture report using frontier LLM
- At‑a‑glance view of outstanding issues
- Sort issues by priority and category
- Be notified of new issues in real time

### 🤖 AI Assistant (Agentic System)
- Intelligent automation that analyzes and resolves security issues automatically
- Three operational modes:
  - **"Do It For Me"** - Fully automatic handling of routine security tasks
  - **"Analyze & Recommend"** - Review AI decisions before execution
  - **"Backend AI Analysis"** - Deep network security scans and comprehensive reports
- Scheduled automation with granular control:
  - **"Auto run"** toggle - Schedule automatic processing at regular intervals (5min/1h/1day)
  - **"Auto confirm"** toggle - Control whether scheduled runs execute safe actions immediately or wait for approval
- Supports multiple LLM providers:
  - **Claude (Anthropic)** - Detailed reasoning and nuanced security decisions
  - **OpenAI (GPT)** - Fast responses and general-purpose analysis
  - **Ollama (Local)** - Privacy-focused, runs entirely on your machine
- Complete transparency with full action history and reasoning
- Undo capability for all automated actions
- **MCP (Model Context Protocol) integration**:
  - Secure localhost-only server (port 3000) with Streamable HTTP transport
  - PSK authentication for external AI tools
  - 9 security automation tools (advisor, score, agentic)
  - Connect Claude Desktop, MCP Inspector, or build custom workflows
  - Test interactively with MCP Inspector: `npx @modelcontextprotocol/inspector --server-url http://127.0.0.1:3000/mcp --transport http`
- Interactive features: email reports, custom security questions
- See [AGENTIC.md](AGENTIC.md) for detailed user guide and MCP testing instructions

### 🛡️ System Security Benchmarks and One-Click Remediations
- Assess your workstation against industry standards, including:
    - CIS Benchmarks
    - SOC 2 / ISO 27001 compliance requirements
    - Privacy requirements
- Visualize all elements comprising your system attack surface with their status in real time
- Automatically fix common system security issues without requiring deep security expertise
    - Get a detailed description of each issue
    - Perform one‑click remediations with technical explanations
- Run batch automated remediations to harden your system with one click
- Keep a history of remediations and roll back if needed

### 🌐 Built‑in Network Scanning (inspired by Nmap)
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

### 📶 Traffic Monitoring (inspired by Wireshark)
- Capture traffic sessions with domain and process context
- At‑a‑glance, real‑time traffic view using sunburst visualization
- Flexible table view of traffic sessions
- Flag blacklisted traffic
- ML‑based traffic anomaly detection
- Anonymized, RAG‑based AI analysis of suspicious sessions
- Flag suspicious sessions as safe when applicable
- Get notifications for new suspicious sessions
- Searchable history of suspicious sessions

### 🔐 Digital Identity Management
- Monitor and manage your online identity exposure
- Integrated with [HaveIBeenPwned.com](https://haveibeenpwned.com)
- Anonymized, RAG‑based AI analysis of data breaches
- Flag breaches as safe when properly handled
- Get notifications about data breaches affecting your email accounts

### 📊 Compliance Reports
- Compute and anonymously sign your current security posture through EDAMAME's backend
- Generate SOC 2 or ISO 27001 one‑click compliance reports and make them available to third parties (employers, partners, etc.)
- Connect to the no‑MDM platform at [hub.edamame.tech](https://hub.edamame.tech), enabling:
   - Continuously report your security posture without compromising privacy to gain access to protected resources
   - Compatible with identity providers (Google, Microsoft), Git platforms (GitHub, GitLab), VPNs (Tailscale, NetBird), and firewalls (Fortinet)

https://github.com/user-attachments/assets/72fb4115-ac79-4267-b79c-fba2a5dfed9e

### Download the Application

| Feature | macOS | Windows | Linux | iOS | Android/ChromeOS |
| --- | --- | --- | --- | --- | --- |
| System | ✓ | ✓ | ✓ | ✓ | ✓ |
| LAN | ✓ | ✓ | ✓ | ✓ | ✓ |
| Identity | ✓ | ✓ | ✓ | ✓ | ✓ |
| Traffic | ✓ | requires Npcap | beta | - | - |
| Helper | mandatory | optional | built-in | none | none |

#### macOS
- Install from [EDAMAME](https://edamame.s3.eu-west-1.amazonaws.com/macos/edamame-latest.pkg) for an all-in-one installation or the [Mac App Store](https://apps.apple.com/app/edamame-security/id1636777324) for an Apple‑vetted sandboxed main app; use EDAMAME to install the [EDAMAME Helper](https://github.com/edamametechnologies/edamame_helper/releases) open‑source system helper for the required system access


#### Windows
1. Install from [EDAMAME](https://edamame.s3.eu-west-1.amazonaws.com/windows/edamame-latest.msix) or the [Microsoft Store](https://www.microsoft.com/store/apps/9N399LMTKQLQ) for a Microsoft vetted sandboxed main app
2. Install the [EDAMAME Helper](https://github.com/edamametechnologies/edamame_helper/releases) open-source system helper for the required system access
3. Install [npcap](https://npcap.com/#download) to enable traffic capture

#### Linux
```bash
# Import GPG key and add repository
wget -O - https://edamame.s3.eu-west-1.amazonaws.com/repo/public.key | sudo gpg --dearmor -o /usr/share/keyrings/edamame.gpg
echo "deb [arch=amd64 signed-by=/usr/share/keyrings/edamame.gpg] https://edamame.s3.eu-west-1.amazonaws.com/repo stable main" | sudo tee /etc/apt/sources.list.d/edamame.list

# Install EDAMAME Security
sudo apt update
sudo apt install edamame-security
```

#### Mobile
- iOS: [App Store](https://apps.apple.com/app/edamame-security-mobile/id6448937722)
- Android/ChromeOS: [Google Play Store](https://play.google.com/store/apps/details?id=com.edamametech.edamame)

## Repository Purpose

This repository serves as the public issue tracker for EDAMAME Security. While the application itself is closed source, we use this space to:

- 📋 Track bug reports and feature requests
- 💬 Engage with the community
- 📢 Share updates and announcements
- 🤝 Collect feedback from users

## Getting Started

To download and use EDAMAME Security, visit [github.com/edamametechnologies](https://github.com/edamametechnologies).

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
