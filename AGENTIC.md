# AI Assistant - User Guide

## Overview

The **AI Assistant** (also called "Agentic" system) is an intelligent automation feature that helps you manage your network security by automatically analyzing and resolving security issues, network alerts, and policy violations.

Think of it as your personal security analyst that:
- 📊 **Analyzes** security recommendations and network events
- 🤖 **Decides** the best course of action based on context
- ⚡ **Executes** or recommends actions automatically
- 📝 **Tracks** everything it does with full transparency

## Key Concepts

### What is a "Todo"?

A **todo** is any actionable security recommendation in your advisor tab:
- 🛡️ **Threats** - Security vulnerabilities that need remediation
- 🔒 **Policy Violations** - Configuration issues to fix
- 🌐 **Network Sessions** - Suspicious connections to review
- 🔌 **Open Ports** - Exposed services to investigate
- 🔐 **Pwned Breaches** - Data breach alerts to acknowledge

### How the AI Helps

Instead of manually reviewing and acting on each todo, the AI Assistant:
1. **Understands context** - Reads the full details of each security issue
2. **Makes smart decisions** - Determines if action is safe and necessary
3. **Takes action** - Dismisses false positives, remediates threats, or escalates complex cases
4. **Explains reasoning** - Shows you why it made each decision

## Workflows

### 🚀 Quick Start: Three Modes

When you click the AI Assistant section in the Advisor tab, you'll see three operational modes:

#### 1. **"Do It For Me"** (Fully Automatic) ⚡
**Use when:** You trust the AI to handle routine security tasks

**What happens:**
- AI analyzes all pending todos
- **Makes "auto_resolve" or "escalate" decision for each**
- **Auto-resolves:** Executes safe actions immediately → status: ✅ Auto-Resolved
- **Escalates:** Flags complex/risky issues for manual review → status: 🟡 Escalated
- Shows you a summary of what was done

**Best for:**
- Daily security maintenance
- Handling false positives
- Clearing routine alerts

**Example:** AI sees 10 network alerts. It auto-resolves 7 (dismisses false positives), auto-resolves 2 (fixes configuration), and escalates 1 (suspicious connection requires your review).

#### 2. **"Analyze & Recommend"** (Review Before Action) 🔍
**Use when:** You want to review AI decisions before they take effect

**What happens:**
- AI analyzes all pending todos **using the same decision logic**
- **Makes "auto_resolve" or "escalate" decision for each**
- **Auto-resolves:** Shows recommendation but waits for your approval → status: 🟠 Requires Confirmation
- **Escalates:** Flags for manual review (same as "Do It For Me") → status: 🟡 Escalated
- You manually confirm or reject each action

**Key Insight:** The AI makes identical decisions in both modes. The only difference is whether "auto_resolve" executes immediately or waits for confirmation.

**Best for:**
- Learning how the AI thinks
- Sensitive environments
- High-security situations

**Example:** AI analyzes the same 10 alerts with the same reasoning, but instead of executing, it shows you "I would dismiss these 9" and waits for your approval on each.

#### 3. **"Backend AI Analysis"** (Deep Scan) 🔬
**Use when:** You want the backend to pre-analyze your network data

**How it works now:**
1. Click **Request report** to start a backend scan. The AI runs in the background and prepares the latest analysis.
2. When processing finishes, a **Read latest report** button appears. Click it to open the dialog with the newest report.

**Behind the scenes:**
- Backend AI scans all network traffic and system data
- Generates new security recommendations
- Creates todos for you to review or for the AI Assistant to process

**Best for:**
- Discovering hidden threats
- Periodic deep security audits
- Finding patterns across your network

### 🔧 Interface Overview

#### Collapsible header & quick context
- The **Agentic** header (with the Beta badge) mirrors `AgenticHeader` and lets you collapse or expand the entire experience with one tap.
- When expanded, every section below stays in sync with the live agentic context returned by `getAgenticContextStream()`.

#### Immediate automation controls
- `AgenticControls` exposes the **Do It For Me** and **Analyze & Recommend** buttons exactly as implemented in the app—both are disabled until an AI provider is configured and nothing is currently running.
- A dedicated **Cancel** button appears while `_isProcessing` is true, giving you an immediate escape hatch without waiting for the backend to finish.

#### Scheduled automation toggles
- The **Auto run** switch is wired to `AgenticService().setAutoProcessing` and supports the same 5 min / 1 h / 1 day intervals (`_intervalOptions = [300, 3600, 86400]`) you see in the UI dropdown.
- The adjacent **Auto confirm** switch maps to the `mode` parameter (0 = auto, 1 = manual), so scheduled jobs can either execute safe actions or pause for approval.
- Both switches stay disabled until your AI provider is fully configured and tested, matching the `isConfigReady` guard in code.

#### Backend AI report controls
- `AgenticBackendControls` now shows two buttons side-by-side:
  1. **Request report** – kicks off the remediation stream (`getAdvisorRemediationStream`) and is automatically disabled while a run is in progress or when prerequisites (LAN, Identity, Capture data) are missing.
  2. **Read latest report** – appears only after `_advisorReportReady` becomes true and opens the same dialog as `_showAdvisorRemediationDialogWithParameter("")`.
- Tooltips surface the same `aiAnalysisNeedConfig` string when configuration is incomplete, so the docs call this out explicitly.

#### MCP server controls (desktop only)
- `AgenticMcpControls` is rendered everywhere but the app purposely hides the button on Android/iOS (`Platform.isAndroid || Platform.isIOS`) because the local MCP server only ships on desktop builds.
- Clicking the hub icon opens the PSK + port configuration dialog exactly like the code path described in the MCP section below.

#### Live workflow status & summaries
- `AgenticStatus` streams the precise workflow phases emitted from `AgenticWorkflowStatusAPI`: **Starting**, **Fetching analysis**, **AI analyzing**, **Decision made**, **Executing**, and finally **Completed**.
- When the workflow emits **Completed**, the widget shows the same aggregated counts you see in the UI (auto-resolved, requires confirmation, escalated, failed).
- The status card doubles as a result banner, reusing the success/failure styling controlled by `resultSuccess`.

### 🎛️ Automated Processing Controls

The AI Assistant provides two powerful toggles for scheduled automation:

#### **"Auto run" Toggle**
Enable scheduled automatic processing of security todos at regular intervals (5 min, 1 hour, or 1 day):

- **When enabled:** AI Assistant automatically runs at your chosen interval
- **When disabled:** You manually trigger "Do It For Me" or "Analyze & Recommend" when needed
- **Best for:** Continuous security monitoring and maintenance

#### **"Auto confirm" Toggle**
Controls whether scheduled runs automatically execute safe actions or just analyze them:

- **When enabled (Auto mode):** Scheduled runs execute "auto_resolve" decisions immediately
  - Safe actions are performed without waiting for approval
  - Escalated items still require manual review
  - Perfect for hands-off security maintenance

- **When disabled (Manual mode):** Scheduled runs only analyze and record decisions
  - All "auto_resolve" decisions wait for your confirmation
  - Nothing is executed automatically
  - You review and approve actions in the UI when convenient
  - Escalated items still flagged for manual review

**Example workflow:**
1. Enable "Auto run" with 1-hour interval
2. Enable "Auto confirm"
3. Result: Every hour, AI processes new security todos and executes safe actions automatically
4. You only see escalated items that need your expertise

**Safety note:** Both toggles appear only when:
- AI provider is configured (Claude, OpenAI, or Ollama)
- API connection is tested and working
- This ensures automation only runs when AI is properly set up

### 📊 Action History

Every action the AI takes is logged in the **Action History** section:

#### Status Types

🟢 **Auto-Resolved** - AI decided "auto_resolve" and executed it (in "Do It For Me" mode)
- Example: Dismissed a false-positive port scan automatically
- Action completed successfully and can be undone

🟠 **Requires Confirmation** - AI decided "auto_resolve" but waiting for approval (in "Analyze & Recommend" mode)
- Example: AI recommends dismissing a port scan, awaiting your confirmation
- Click "Confirm" to execute, same reasoning as Auto-Resolved

🟡 **Escalated** - AI decided "escalate" (too complex or risky to auto-resolve)
- Example: Critical security policy change, suspicious network pattern
- Always requires manual review regardless of mode
- Includes priority level (low/medium/high/critical)

🔴 **Failed** - Action couldn't be completed (LLM error, execution error, timeout)
- Example: API timeout, network connectivity issue, invalid credentials
- Click "Retry" to attempt again
- Check error details for troubleshooting hints

⚪ **Obsolete** - Todo was resolved by other means (dismissed manually or fixed)
- Example: User manually fixed the issue before AI could process it
- Cannot be executed or undone (no longer relevant)

#### Action History Features

- 🔗 **Open native context** – The **View Details** action launches the same Remed, LANscan, Capture, or Pwned cards used elsewhere in the Advisor tab (see `_navigateToActionDetail` in code).
- 🧠 **Detailed action cards** – Each entry exposes timestamps, processing duration, token counts, undo info, and priority exactly as defined in `AgenticActionDetailsCard`.

**Filtering:**
- Filter by status (Auto-resolved, Requires confirmation, Escalated, Failed)
- Filter by type (Threats, Network, Policies, Breaches)

**Bulk Actions:**
- **Confirm All** - Approve all pending confirmations at once
- **Undo All** - Revert all AI actions in one click
- **Clear History** - Remove old completed actions

**Individual Actions:**
- 👁️ **View Details** - See full reasoning and technical details
-**Confirm** - Execute a recommended action
- ↩️ **Undo** - Revert a completed action
- 🔄 **Retry** - Attempt a failed action again

### 🎯 Decision Flow

Here's how the AI makes decisions:

```
Todo Received
    ↓
AI Analyzes Context
    ↓
AI Makes ONE of TWO Decisions:
    ↓
    ├─→ [Safe & Routine] → "auto_resolve" decision
    │       ↓
    │       ├─→ [Do It For Me mode] → Execute Immediately → ✅ Auto-Resolved
    │       └─→ [Analyze & Recommend mode] → Present for Review → 🟠 Requires Confirmation
    │
    └─→ [Complex/Risky] → "escalate" decision → 🟡 Human Review Needed (Escalated)

If any step fails (LLM error, execution error, etc.) → 🔴 Failed (Retry Available)
```

**Important:** The AI only makes **two types of decisions**:
1. **"auto_resolve"** - The action is safe and routine
2. **"escalate"** - The action is complex or risky

The difference between ✅ **Auto-Resolved** and 🟠 **Requires Confirmation** is **which mode you used**, not what the AI decided:
- Same AI decision ("auto_resolve")
- Different user mode determines execution:
  - **"Do It For Me"** → Executes automatically (Auto-Resolved)
  - **"Analyze & Recommend"** → Waits for your approval (Requires Confirmation)

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

## Technology Stack

### Large Language Models (LLMs)

The AI Assistant uses advanced language models to understand and reason about security issues:

**Supported Providers:**

#### 1. **Claude (Anthropic)** 🎨
- **Models:** Claude Sonnet 4.5, Claude Haiku 4.5
- **Best for:** Detailed reasoning, nuanced security decisions
- **Requires:** API key from console.anthropic.com
- **Cost:** Pay-per-use (most expensive but highest quality)

#### 2. **OpenAI (GPT)** 🤖
- **Models:** GPT-5, GPT-5 Mini
- **Best for:** Fast responses, general-purpose analysis
- **Requires:** API key from platform.openai.com
- **Cost:** Pay-per-use (medium cost, good quality)

#### 3. **Ollama (Local)** 💻
- **Models:** Any model you run locally (llama3, mistral, etc.)
- **Best for:** Privacy-conscious users, no internet dependency
- **Requires:** Ollama installed locally, custom base URL
- **Cost:** Free (runs on your hardware)

### Model Context Protocol (MCP) integration

**What is MCP?**
MCP is a protocol that lets LLMs securely access external tools and data. In EDAMAME Security:

- **MCP Server** runs locally on your machine
- **LLM** connects to it over a secure channel (with PSK authentication)
- **Tools** exposed to LLM include everything the app does, system remediations, network and traffic scanning, etc.

**Setup:**
1. Generate a PSK (Pre-Shared Key) in the MCP Server dialog
2. Start the MCP server on a local port (default: 3000)
3. Configure your LLM provider to connect to the server
4. AI can now execute actions through MCP tools

### Privacy & Security

**Your data:**
- Todo data is sent to the LLM for analysis (encrypted in transit)
- Context is sanitized before being sent to the LLM (see `edamame_foundation` for the open-source code used)
- You control what the AI can do (undo capability on all actions)
- All actions are logged and transparent

**With Ollama (local LLM):**
- **Zero cloud dependency**: everything runs locally
- **Complete privacy**: no data leaves your machine
- **Full control**: you manage the model and its behavior

**Best Practices:**
- Start with "Analyze & Recommend" mode to learn the AI's behavior
- Review action history regularly
- Use undo if the AI makes a mistake
- Report issues to improve the system

## Configuration

### Setting Up Your AI Provider

1. **Open Settings**
   - Click the ⚙️ icon next to "Do It For Me" button

2. **Choose Provider**
   - Select Claude, OpenAI, or Ollama

3. **Enter Credentials**
   - **Claude/OpenAI:** Enter API key
   - **Ollama:** Enter base URL (e.g., `http://localhost:11434`)

4. **Select Model**
   - Choose from available models for your provider

5. **Test Connection**
   - Click "Test Connection" to verify setup
   - You should see ✅ success message

6. **Save & Close**
   - Configuration is automatically saved on successful test

### MCP Server Setup (Optional - For Advanced Users)

**What is MCP?**
MCP (Model Context Protocol) allows external AI tools like Claude Desktop to connect to EDAMAME and control it securely. Think of it as an API for AI assistants.

**When to use it:**
- You want to use Claude Desktop to manage your security
- You're building automation workflows (n8n, Zapier)
- You want to test the AI features programmatically

**Setup:**

1. **Open MCP Dialog**
   - Click the 🔌 hub icon next to AI settings

2. **Generate PSK** (Pre-Shared Key)
   - Click "Generate PSK" to create a secure authentication key
   - Copy and save it securely (you'll need this for clients)

3. **Configure Port**
   - Default: 3000 (change if port is in use)
   - Server only binds to localhost (127.0.0.1) for security

4. **Start Server**
   - Click "Enable MCP Server"
   - Server runs in background on port 3000
   - Status shows: "Running on port 3000"

5. **Connect External Clients**
   - **Claude Desktop**: Add to configuration (see below)
   - **MCP Inspector**: Test interactively (see testing section)
   - **Custom clients**: Use the MCP protocol

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
        "Authorization: Bearer YOUR_PSK_HERE"
      ]
    }
  }
}
```

Replace `YOUR_PSK_HERE` with the PSK from step 2.

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

### Testing Your MCP Server

**MCP Inspector** is a free interactive tool to test and debug MCP servers.

**Quick Test (5 minutes):**

**Step 1: Ensure MCP Server is Running**
- Open EDAMAME app → AI Assistant settings
- Verify "MCP Server: Running on port 3000"
- Have your PSK ready

**Step 2: Launch Inspector**

```bash
npx @modelcontextprotocol/inspector \
  --server-url http://127.0.0.1:3000/mcp \
  --transport http
```

**Step 3: Configure Authentication in Inspector UI**

When Inspector opens in your browser:
1. Click "Custom Headers"
2. Add header name: `Authorization`
3. Add header value: `Bearer YOUR_PSK_HERE`

Replace `YOUR_PSK_HERE` with your actual PSK from Step 1.

**Step 4: Test in Browser**

Inspector opens at `http://localhost:5173` and shows:
-Connection: "Connected" (green)
-Tools: 9 tools listed (advisor, score, agentic)
-Interactive: Click any tool → Enter params → See results

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
  - Verify server is running in EDAMAME app
  - Use `127.0.0.1` not `localhost` in URL
  - Test: `curl http://127.0.0.1:3000/health` (should return "OK")

- **401 Unauthorized?**
  - Check PSK is correct (copy fresh from app)
  - Verify format: `Authorization: Bearer <psk>` (note space after "Bearer")

- **No tools showing?**
  - Wait 2-3 seconds after connection
  - Refresh browser page (F5)

### Backend AI Analysis Setup

The backend AI performs a holistic analysis of your security posture and generates comprehensive reports:

#### 1. **Enable Backend Analysis**
   - Configure monitoring features first:
     - 🔐 **Breach Detection** (Identity tab)
     - 🌐 **LAN Scanning** (LAN tab)  
     - 📡 **Traffic Monitoring** (Capture tab - requires Helper)

#### 2. **Request a Report**
   - Click the **"Request report"** button in the AI Assistant section (it stays disabled until the prerequisites in the Advisor tab are satisfied, mirroring the `aiAnalysisDisabled` flag in code)
   - What happens:
     1. A sanitized version of your most important todos is sent to the backend
     2. Backend AI generates a comprehensive security report in the background
     3. Once ready, the **"Read latest report"** button becomes available

#### 3. **Read & Interact**
   - Click **"Read latest report"** to open the dialog with the newest analysis

#### 3. **Interactive Features**

Once the report is displayed, you can:

**📧 Request Report via Email**
- Click "Request Report" button
- Provide your email address
- Receive the full analysis report in your inbox
- Useful for sharing with IT teams or keeping records

**💬 Ask Custom Questions**
- Click "Ask a Question" button
- Enter your specific security question (e.g., "Why is port 22 open on my router?")
- Backend AI generates a focused answer based on your current security state
- Great for understanding specific alerts or getting targeted advice

**Example Flow:**
1. Click "Request report" → Backend AI prepares your holistic security report
2. When prompted, click "Read latest report" → View the analysis dialog
3. Click "Ask a Question" → "Is my home network secure enough for remote work?"
4. Get specific recommendations → Click "Request Report" (in-dialog) → Receive full analysis via email

## Tips & Best Practices

### 🎓 Learning Phase
1. Start with **"Analyze & Recommend"** mode
2. Review AI reasoning for each decision
3. Understand patterns before switching to auto mode
4. Use the "View Details" button to see full context

### ⚡ Production Use
1. Use **"Do It For Me"** for daily maintenance
2. Review Action History regularly (weekly)
3. Investigate escalated items promptly

### 🛡️ Security Hardening
1. Use **Ollama locally** for maximum privacy
2. Enable MCP server only when needed
3. Use strong PSK for MCP authentication
4. Monitor failed actions for potential issues

### 🔄 Troubleshooting
1. **AI not responding?** Check API key and test connection again
2. **Wrong decisions?** Use undo and provide feedback
3. **Failed actions?** Check network connectivity and retry

## FAQ

**Q: What's the difference between "Do It For Me" and "Analyze & Recommend"?**
A: The AI makes the same decisions in both modes. The difference is execution:
- **Do It For Me:** AI executes safe actions immediately (you see "Auto-Resolved")
- **Analyze & Recommend:** AI shows you what it would do but waits for your approval (you see "Requires Confirmation")

In both modes, risky/complex actions are escalated for manual review. Use "Analyze & Recommend" to learn what the AI considers safe before switching to "Do It For Me."

**Q: How much does it cost?**
A: Depends on your provider:
- Claude/OpenAI: pay-per-use
- Ollama: Free (runs locally)

**Q: Can I use it offline?**
A: Yes, with Ollama. Configure it to run locally and the AI works without internet.

**Q: What happens if I disagree with the AI?**
A: Click "Undo" on any action.

**Q: Is my data private?**
A: With cloud providers (Claude/OpenAI), context is sanitized (see edamame_foundation for the open source code used) and is sent directly to their API (encrypted). With Ollama, everything stays local. 

**Q: Can I customize AI behavior?**
A: Currently, choose "Analyze & Recommend" mode for full control.

**Q: How do I know the AI made the right decision?**
A: Every action includes full reasoning in the Action History. Click "View Details" to see the AI's thought process.

## Getting Started Checklist

- [ ] Configure AI provider (Claude, OpenAI, or Ollama)
- [ ] Test connection successfully
- [ ] Try "Analyze & Recommend" mode first
- [ ] Review 5-10 AI decisions to understand reasoning
- [ ] Switch to "Do It For Me" when comfortable

