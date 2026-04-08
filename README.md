<div align="center">

# 🎯 HunterAI

### Autonomous AI Bug Bounty Engine for Claude Code

*One command. Zero questions. Verified vulnerability reports out.*

<br>

[![Claude Code](https://img.shields.io/badge/Claude_Code-Plugin-D97706.svg?style=flat-square&logo=anthropic&logoColor=white)](https://claude.ai)
[![Kali Linux](https://img.shields.io/badge/Kali_Linux-Ready-557C94.svg?style=flat-square&logo=kalilinux&logoColor=white)](https://kali.org)
[![Python 3.8+](https://img.shields.io/badge/Python-3.8+-3776AB.svg?style=flat-square&logo=python&logoColor=white)](https://python.org)
[![Tools](https://img.shields.io/badge/Tools-90+-green.svg?style=flat-square)]()
[![MCP](https://img.shields.io/badge/MCP-Burp_+_H1-blue.svg?style=flat-square)]()

</div>

---

## What Is This?

HunterAI turns Claude Code into a **fully autonomous bug bounty hunting engine**. Give it a HackerOne program name — it collects scope, runs recon, finds vulnerabilities, validates them with PoCs, and generates submission-ready reports. No manual steps.

```
You type:  /fullhunt rockstargames
You get:   Verified vulnerability reports with PoCs in reports/rockstargames/
```

---

## Table of Contents

- [Quick Start](#quick-start)
- [Installation](#installation)
  - [Prerequisites](#prerequisites)
  - [Step 1: Clone](#step-1-clone)
  - [Step 2: Install Dependencies](#step-2-install-dependencies)
  - [Step 3: Configure API Keys](#step-3-configure-api-keys)
  - [Step 4: Verify Installation](#step-4-verify-installation)
- [MCP Integration](#mcp-integration-burp--hackerone)
- [Usage](#usage)
- [How It Works](#how-it-works)
- [What It Finds](#what-it-finds)
- [Architecture](#architecture)
- [Session Persistence](#session-persistence)
- [Project Structure](#project-structure)
- [Troubleshooting](#troubleshooting)
- [Disclaimer](#disclaimer)

---

## Quick Start

```bash
# Clone
git clone https://github.com/1fanya/hunterAI.git
cd hunterAI

# Install everything
chmod +x setup_hunter.sh && ./setup_hunter.sh

# Configure API keys
cp .env.example .env
nano .env  # Fill in your tokens (see table below)

# Load env and verify
export $(grep -v '^#' .env | xargs)
python3 tools/smoke_test.py

# Hunt!
claude --dangerously-skip-permissions
# Then type: /fullhunt <program-name>
```

---

## Installation

### Prerequisites

| Requirement | Version | Notes |
|---|---|---|
| **Kali Linux** | 2024.1+ | WSL2 or native. Terminal only, no GUI needed |
| **Python** | 3.8+ | Pre-installed on Kali |
| **Go** | 1.21+ | For ProjectDiscovery tools |
| **Claude Code** | Latest | `npm install -g @anthropic-ai/claude-code` |
| **Claude Pro** | Required | For autonomous hunting (token limits) |

### Step 1: Clone

```bash
git clone https://github.com/1fanya/hunterAI.git
cd hunterAI
```

### Step 2: Install Dependencies

#### Option A: Automated install (recommended)

```bash
chmod +x setup_hunter.sh && ./setup_hunter.sh
```

This installs:
- **Python packages**: `requests`, `aiohttp`, `playwright`, `nvdlib`
- **Browser**: Chromium (for Playwright PoCs)
- **Go tools**: `subfinder`, `httpx`, `katana`, `nuclei`, `gau`, `subzy`
- **System tools**: `sqlmap`, `ffuf`, `nmap`, `commix`, `dalfox`, `xsstrike`

#### Option B: Manual install

```bash
# Python deps (Kali uses --break-system-packages)
pip install --break-system-packages requests aiohttp playwright nvdlib

# Browser for PoCs
playwright install chromium

# Go tools (ProjectDiscovery)
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
go install -v github.com/projectdiscovery/katana/cmd/katana@latest
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install -v github.com/lc/gau/v2/cmd/gau@latest

# Add Go bin to PATH
echo 'export PATH=$PATH:$HOME/go/bin' >> ~/.bashrc
source ~/.bashrc
```

### Step 3: Configure API Keys

```bash
cp .env.example .env
nano .env
```

Fill in the following tokens:

| Variable | Where to Get It | Priority |
|---|---|---|
| `H1_API_TOKEN` | [hackerone.com/settings/api_token](https://hackerone.com/settings/api_token) | 🔴 **Required** |
| `H1_API_USERNAME` | Your HackerOne username (same page as above) | 🔴 **Required** |
| `TELEGRAM_BOT_TOKEN` | [t.me/BotFather](https://t.me/BotFather) → `/newbot` → copy token | 🟡 Recommended |
| `TELEGRAM_CHAT_ID` | [t.me/userinfobot](https://t.me/userinfobot) → send `/start` → copy ID | 🟡 Recommended |
| `GITHUB_TOKEN` | [github.com/settings/tokens](https://github.com/settings/tokens) → Generate new token (classic), no scopes needed | 🟡 Recommended |
| `SHODAN_API_KEY` | [account.shodan.io](https://account.shodan.io) → API Key tab | 🟡 Recommended |
| `NVD_API_KEY` | [nvd.nist.gov/developers](https://nvd.nist.gov/developers/request-an-api-key) — free, 10x rate boost | 🟡 Recommended |
| `INTERACTSH_URL` | [github.com/projectdiscovery/interactsh](https://github.com/projectdiscovery/interactsh) → `go install` → run `interactsh-client` → copy URL | 🟡 Recommended |
| `BURP_API_URL` | Default: `http://127.0.0.1:1337` | 🟢 Optional |
| `BURP_API_KEY` | Burp Suite REST API settings | 🟢 Optional |
| `HUNT_AUTH_TOKEN` | Set per-target during auth testing | 🟢 Optional |
| `HUNT_COOKIES` | Set per-target during auth testing | 🟢 Optional |
| `ZENDESK_SUBDOMAIN` | Set per-target for Zendesk testing | 🟢 Optional |
| `ZENDESK_EMAIL` | Set per-target for Zendesk testing | 🟢 Optional |
| `ZENDESK_API_TOKEN` | Set per-target for Zendesk testing | 🟢 Optional |

Load your env before starting:

```bash
export $(grep -v '^#' .env | xargs)
```

> **Tip:** Add this line to `~/.bashrc` so env vars load automatically:
> ```bash
> echo 'cd ~/hunterAI && export $(grep -v "^#" .env | xargs) 2>/dev/null' >> ~/.bashrc
> ```

### Step 4: Verify Installation

```bash
python3 tools/smoke_test.py
```

Expected output:
```
╔══════════════════════════════════════════════════════╗
║          HunterAI Smoke Test                         ║
╚══════════════════════════════════════════════════════╝

  DEPENDENCY CHECK       ✓ all passed
  TOOL MODULE CHECK      ✓ 91 modules loaded
  EXTERNAL TOOLS CHECK   ✓ subfinder, httpx, nuclei ...
  ENV CHECK              ✓ H1_API_TOKEN set
```

---

## MCP Integration (Burp + HackerOne)

HunterAI includes two **MCP servers** that give Claude Code direct access to Burp Suite and HackerOne.

### Setup MCP Servers

```bash
# Automated setup
chmod +x mcp/setup_mcp.sh && ./mcp/setup_mcp.sh

# Or manually register with Claude Code:
claude mcp add hackerone -- python3 mcp/hackerone-mcp/server.py
claude mcp add burp --env BURP_API_URL=http://127.0.0.1:1337 -- python3 mcp/burp-mcp-client/server.py

# Verify
claude mcp list
```

### HackerOne MCP — 7 Tools

| Tool | Auth | What It Does |
|---|---|---|
| `search_disclosed_reports` | No | Search Hacktivity for dupes/intel |
| `get_program_stats` | No | Bounty ranges, response SLAs |
| `get_program_policy` | No | Scope, rules, safe harbor |
| `get_my_reports` | Yes | List your submitted reports |
| `add_report_comment` | Yes | Comment on a report |
| `close_report` | Yes | Self-close a report |
| `get_program_scope_auth` | Yes | Detailed authenticated scope |

Test it:
```bash
python3 mcp/hackerone-mcp/server.py search "ssrf" --limit 5
python3 mcp/hackerone-mcp/server.py stats rockstargames
```

### Burp Suite MCP — 7 Tools

| Tool | What It Does |
|---|---|
| `get_proxy_history` | Fetch intercepted requests/responses |
| `search_proxy` | Search by URL, method, status code |
| `get_sitemap` | Discovered URLs from sitemap |
| `send_to_repeater` | Send crafted request to Repeater |
| `start_active_scan` | Launch active scan on a URL |
| `get_scan_status` | Scan findings and progress |
| `get_issue_definitions` | Burp issue type reference |

> **Note:** Burp Suite must be running with REST API enabled:
> ```bash
> java -jar burpsuite_pro.jar --rest-api --rest-api-key=YOUR_KEY
> ```

---

## Usage

### Start a Hunt

```bash
# Load environment
export $(grep -v '^#' .env | xargs)

# Start Claude Code in permissive mode
claude --dangerously-skip-permissions
```

Then inside Claude Code:

```
/fullhunt <program-handle>      # Full autonomous hunt (scope → report)
/resume <program-handle>        # Resume after rate limits
```

### All Commands

| Command | What It Does |
|---|---|
| `/fullhunt <program>` | **Full autonomous hunt** — scope to reports, zero questions |
| `/resume <program>` | Resume after limits reset — continues exactly where stopped |
| `/recon <domain>` | Recon only — subdomains, live hosts, URLs |
| `/hunt <domain>` | Active hunting on ranked endpoints |
| `/validate` | Run 7-Question Gate on findings |
| `/report` | Generate HackerOne-ready report |
| `/compare` | Check finding against Hacktivity for duplicates |
| `/methodology` | View the 7-phase hunting methodology |
| `/monitor <domain>` | Background recon for new attack surface |

### Example Session

```
Session 1:  /fullhunt shopify
            ✅ Scope imported → Recon → Ranking → Hunting 15 endpoints...
            ⏸️  Rate limit hit → state auto-saved to hunt-memory/

Session 2:  /resume shopify
            ✅ Hunting remaining 30 endpoints → Validation → Dedup...
            ⏸️  Rate limit hit → state auto-saved

Session 3:  /resume shopify
            ✅ Final reports generated → reports/shopify/
            📱 Telegram alert: "3 validated findings ready for submission"
```

---

## How It Works

```
/fullhunt <program>
    │
    ├── Phase 0: Program Intel     h1_collector.py → scope, rules, bounty table
    ├── Phase 1: Recon             subfinder + httpx + katana + gau + waybackurls
    ├── Phase 2: Analysis          js_analyzer.py + tech_profiler.py + js_deps_scanner.py
    ├── Phase 3: Ranking           AI ranks endpoints → P1 (test) / P2 (maybe) / Kill
    ├── Phase 4: Hunting           90+ tools test every P1 endpoint across 24 vuln classes
    ├── Phase 5: Verification      exploit_verifier.py → concrete PoC + 7-Question Gate
    ├── Phase 6: Dedup             report_comparer.py → check against Hacktivity
    ├── Phase 7: CVE Check         cve_engine.py → NVD + CISA KEV + ExploitDB + Metasploit
    └── Phase 8: Report            HackerOne-ready report with CVSS + impact + PoC
```

**Fully autonomous** — Claude makes ALL decisions. No prompts, no confirmations. It tests every attack vector in priority order, validates findings with real PoCs, and only reports what passes the 7-Question Gate.

### 7-Question Validation Gate

Every finding must pass before reporting:

1. ✅ Can I reproduce it right now with a curl/script?
2. ✅ Does it affect a real user/data, not just a test account?
3. ✅ Is the impact beyond self-DoS or cosmetic?
4. ✅ Is it in scope per the program policy?
5. ✅ Does it require realistic user interaction (or none)?
6. ✅ Have I checked Hacktivity for duplicates?
7. ✅ Would I mass-close this if I were the triager?

---

## What It Finds

| Vulnerability Class | Tool(s) | OWASP |
|---|---|---|
| IDOR / Auth Bypass | `auth_tester.py`, `idor_scanner.py` | A01 |
| SQL Injection | `sqlmap` + `exploit_verifier.py` | A03 |
| Command Injection / SSTI | `commix` + `exploit_verifier.py` | A03 |
| XSS (Reflected/Stored/DOM) | `dalfox` + `xsstrike` + `blind_xss.py` | A03 |
| SSRF | `exploit_verifier.py` + `interactsh` | A10 |
| OAuth Misconfig | `oauth_tester.py` | A07 |
| JWT Attacks | `jwt_tester.py` | A07 |
| GraphQL IDOR/Batching | `graphql_exploiter.py` | A01 |
| CORS Misconfig | `cors_tester.py` | A05 |
| HTTP Smuggling | `smuggling_tester.py` | A05 |
| Race Conditions | `race_tester.py` | A04 |
| Subdomain Takeover | `subdomain_takeover.py` + `subzy` | A05 |
| Cloud Misconfig (S3/Azure/GCP) | `cloud_enum.py` | A05 |
| Secret Leaks (.git/GitHub) | `git_dorker.py` + `trufflehog` | A02 |
| Known CVEs | `cve_engine.py` + `nuclei` (10K+ templates) | A06 |
| XXE Injection | `xxe_scanner.py` | A05 |
| Host Header Injection | `host_header.py` | A05 |
| Cache Poisoning | `cache_poison.py` | A05 |
| **Business Logic** | **Claude AI reasoning** 🧠 | A04 |

---

## Architecture

### 90+ Python Tools (`tools/`)

Custom-built exploitation tools — each handles a specific vulnerability class with rate limiting, scope checking, and structured output.

**Key tools:**
- **Recon**: `subdomain_enum.py`, `tech_profiler.py`, `wayback_analyzer.py`, `cert_monitor.py`
- **Analysis**: `js_analyzer.py`, `js_deps_scanner.py`, `apk_analyzer.py`
- **OSINT**: `github_dorker.py`, `shodan_recon.py`, `git_recon.py`
- **Exploitation**: `payload_mutator.py` (WAF bypass), `browser_auto.py` (Playwright PoCs)
- **CVE Engine**: `cve_engine.py` (NVD + CISA KEV + ExploitDB + Metasploit)
- **Orchestration**: `h1_api.py`, `multi_target.py`, `nuclei_templater.py`
- **Alerts**: `telegram_notifier.py` (real-time findings to your phone)

### MCP Servers (`mcp/`)

- **HackerOne MCP** — 7 tools for program intel, report management
- **Burp Suite MCP** — 7 tools for proxy history, scanning, repeater

### 8 Specialized AI Agents

| Agent | Role |
|---|---|
| `fullhunt-orchestrator` | Master pipeline controller |
| `recon-agent` | Subdomain + URL discovery |
| `recon-ranker` | Attack surface prioritization |
| `autopilot` | Autonomous hunt loop |
| `validator` | 7-Question Gate enforcement |
| `chain-builder` | Multi-vuln A→B→C chains |
| `report-writer` | HackerOne report generation |
| `web3-auditor` | Smart contract auditing |

### 24-Class Exhaustive Hunting

Every `/fullhunt` must test ALL 24 vulnerability classes before generating a report. No early stopping — more bugs = more bounties.

---

## Session Persistence

State is saved to `hunt-memory/` after **every tool call**. If rate limits hit mid-hunt, `/resume` picks up from exactly where it stopped.

```
hunt-memory/
├── <program>/
│   ├── state.json          # Current phase, progress
│   ├── recon_results.json  # Subdomains, URLs, tech stack
│   ├── ranked_targets.json # P1/P2/Kill classification
│   ├── findings.json       # Validated findings
│   └── tested_classes.json # Which of 24 classes are done
```

---

## Project Structure

```
hunterAI/
├── CLAUDE.md                # Master rules for Claude Code (start here)
├── .env.example             # All 15 env vars with instructions
├── setup_hunter.sh          # Automated installer
│
├── tools/                   # 90+ Python exploitation tools
│   ├── smoke_test.py        # Verify all tools load correctly
│   ├── exploit_verifier.py  # PoC validation engine
│   ├── h1_api.py            # HackerOne API client
│   ├── cve_engine.py        # NVD + CISA KEV + ExploitDB
│   ├── telegram_notifier.py # Real-time alerts
│   └── ...                  # 85+ more tools
│
├── mcp/                     # MCP servers for Claude Code
│   ├── hackerone-mcp/       # HackerOne integration (7 tools)
│   ├── burp-mcp-client/     # Burp Suite integration (7 tools)
│   ├── setup_mcp.sh         # MCP auto-installer
│   └── .env.example         # Env template
│
├── commands/                # Slash command definitions
│   ├── fullhunt.md          # /fullhunt pipeline
│   ├── resume.md            # /resume session restore
│   └── methodology.md       # 7-phase methodology
│
├── agents/                  # 8 specialized AI agents
├── rules/                   # Hunting rules + OWASP knowledge
├── hunt-memory/             # Session persistence (auto-created)
└── reports/                 # Generated reports (auto-created)
```

---

## Troubleshooting

### Common Issues

| Problem | Fix |
|---|---|
| `ModuleNotFoundError` | Run `pip install --break-system-packages <module>` |
| `playwright: not found` | Run `playwright install chromium` |
| `subfinder: command not found` | Run `go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest` and add `~/go/bin` to PATH |
| Rate limits during hunt | Just run `/resume <program>` — picks up where it stopped |
| Burp MCP can't connect | Make sure Burp is running with `--rest-api` flag |
| H1 MCP auth fails | Check `H1_API_TOKEN` and `H1_API_USERNAME` are set in `.env` |
| Smoke test shows warnings | Run `python3 tools/smoke_test.py` to see which tools need deps |
| WAF blocks automated browser | Use your real browser for PoC validation, not Playwright |

### Verify Everything Works

```bash
# Check all Python tools
python3 tools/smoke_test.py

# Check external tools
which subfinder httpx katana nuclei ffuf sqlmap

# Check env vars
echo $H1_API_TOKEN | head -c 5  # Should print first 5 chars

# Check MCP
claude mcp list  # Should show hackerone + burp
```

---

## Disclaimer

**⚠️ For authorized security testing only.**

- Only test targets within an approved bug bounty program scope
- Never test systems without explicit written permission
- Follow responsible disclosure practices
- You are solely responsible for how you use this tool

---

<div align="center">

**Built to hunt. 🎯**

*90+ tools · 24 vulnerability classes · MCP Burp/H1 · Zero questions asked*

</div>
