<div align="center">

# 🎯 HunterAI

### Autonomous AI Bug Bounty Hunter for Claude Code

*One command. Zero questions. Vulnerability reports out.*

<br>

[![Claude Code](https://img.shields.io/badge/Claude_Code-Plugin-D97706.svg?style=flat-square&logo=anthropic&logoColor=white)](https://claude.ai)
[![Kali Linux](https://img.shields.io/badge/Kali_Linux-Ready-557C94.svg?style=flat-square&logo=kalilinux&logoColor=white)](https://kali.org)
[![Python 3.8+](https://img.shields.io/badge/Python-3.8+-3776AB.svg?style=flat-square&logo=python&logoColor=white)](https://python.org)

</div>

<br>

---

## What Is This?

HunterAI turns Claude Code into a **fully autonomous bug bounty hunting engine**. You give it a HackerOne program name — it collects scope, runs recon, finds vulnerabilities, verifies them with PoCs, and generates submission-ready reports. No manual steps, no questions asked.

```
You type:  /fullhunt rockstargames
You get:   Verified vulnerability reports with PoCs in reports/rockstargames/
```

---

## Quick Start

```bash
# 1. Clone and install (Kali Linux)
git clone https://github.com/1fanya/hunterAI.git
cd hunterAI
chmod +x install_tools.sh && ./install_tools.sh

# 2. Set API keys
export H1_API_TOKEN="your-hackerone-api-token"
export GITHUB_TOKEN="your-github-token"  # optional

# 3. Hunt
cd ~/hunterAI
claude --dangerously-skip-permissions
/fullhunt rockstargames

# 4. Resume after limits reset
/resume rockstargames
```

---

## How It Works

```
/fullhunt rockstargames
    │
    ├── Phase 0: Program Intel     h1_collector.py → scope, rules, bounty table
    ├── Phase 1: Recon             subfinder + httpx + katana + gau + waybackurls
    ├── Phase 2: Analysis          js_analyzer.py + tech_profiler.py
    ├── Phase 3: Ranking           AI ranks endpoints → P1/P2/Kill
    ├── Phase 4: Hunting           23 tools test every P1 endpoint
    ├── Phase 5: Verification      exploit_verifier.py → concrete PoC
    ├── Phase 6: Dedup             report_comparer.py → check against Hacktivity
    └── Phase 7: Report            HackerOne-ready report with CVSS + impact
```

**Fully autonomous** — Claude makes ALL decisions. No prompts, no confirmations, no "which attack first?" questions. It tests every attack vector in priority order automatically.

---

## What It Finds

| Vulnerability | Tool | OWASP |
|---|---|---|
| IDOR / Auth Bypass | `auth_tester.py` | A01 |
| SQL Injection | `sqlmap` + `exploit_verifier.py` | A03 |
| Command Injection / SSTI | `commix` + `exploit_verifier.py` | A03 |
| XSS (Reflected/Stored/DOM) | `dalfox` + `xsstrike` | A03 |
| SSRF | `exploit_verifier.py` + `interactsh` | A10 |
| OAuth Misconfig | `oauth_tester.py` | A07 |
| JWT Attacks | `jwt_tester.py` | A07 |
| GraphQL IDOR/Batching | `graphql_exploiter.py` | A01 |
| CORS Misconfig | `cors_tester.py` | A05 |
| HTTP Smuggling | `smuggling_tester.py` | A05 |
| Race Conditions | `exploit_verifier.py` | A04 |
| Subdomain Takeover | `subdomain_takeover.py` + `subzy` | A05 |
| Cloud Misconfig (S3/Azure/GCP) | `cloud_enum.py` | A05 |
| Secret Leaks (.git/GitHub) | `git_dorker.py` + `trufflehog` | A02 |
| Known CVEs | `nuclei` (10K+ templates) | A06 |
| **Business Logic** | **Claude thinking** 🧠 | A04 |

Claude doesn't just run tools — it **thinks** about what each endpoint does and tests business logic attacks that no scanner can find (price manipulation, workflow bypass, race conditions).

---

## Architecture

### 70+ Python Tools
Custom-built exploitation tools in `tools/` — each handles a specific vulnerability class with rate limiting, scope checking, and structured output. Includes CVE engine (NVD + CISA KEV + ExploitDB + Metasploit), WAF bypass payload mutator, Playwright browser automation, GitHub dorking, Shodan recon, Wayback Machine analysis, and more.

### 15+ External CLI Tools
ProjectDiscovery suite (subfinder, httpx, katana, nuclei), ffuf, sqlmap, dalfox, commix, xsstrike, arjun, nmap, msfconsole, searchsploit, and more. All installed by `setup_hunter.sh`.

### 24-Class Exhaustive Hunting
Every `/fullhunt` must test ALL 24 vulnerability classes (IDOR, auth bypass, business logic, race conditions, SSRF, SQLi, XSS, etc.) before generating a final report. No early stopping.

### CVE/Exploit Engine
Automatic version detection → NVD API → CISA KEV → ExploitDB → Metasploit module matching. Known vulnerable versions get auto-exploited.

### Real-Time Alerts
Telegram bot pushes findings, CVE matches, and hunt status to your phone instantly.

### OWASP Top 10 Knowledge
`rules/owasp_top10.md` — deep testing knowledge for every OWASP category with specific payloads, curl commands, and mental models for finding bugs tools can't detect.

### Smart Model Routing
Haiku for cheap recon, Sonnet for hunting (quality), configurable per-task. Token optimization with output budgets and batch commands.

### Session Persistence
State saved after **every single tool call**. If limits hit mid-hunt, `/resume` picks up from exactly where it stopped — at most 2-5 minutes of work lost.

### Pattern Learning
`pattern_learner.py` remembers what worked across hunts. Successful techniques on Target A get suggested on Target B with similar tech stack.

---

## Commands

| Command | What It Does |
|---|---|
| `/fullhunt <program>` | **Full autonomous hunt** — scope to reports, zero questions |
| `/resume <program>` | Resume after limits reset — continues exactly where stopped |
| `/recon <domain>` | Recon only — subdomains, live hosts, URLs |
| `/hunt <domain>` | Active hunting on ranked endpoints |
| `/validate` | 7-Question Gate on findings |
| `/report` | Generate HackerOne-ready report |
| `/compare` | Check finding against Hacktivity (dedup) |
| `/methodology` | 7-phase professional hunting methodology |
| `/monitor <domain>` | Background recon for new attack surface |

---

## Session Persistence

```
Session 1:  /fullhunt rockstargames
            ✅ Scope → Recon → Rank → Hunt 15 endpoints
            ⏸️ Limits hit → state auto-saved

Session 2:  /resume rockstargames  
            ✅ Hunt remaining 30 endpoints → Validate → Report
            ⏸️ Limits hit → state auto-saved

Session 3:  /resume rockstargames
            ✅ Finish reports → Done
```

---

## Requirements

- **Kali Linux** (terminal only, no GUI needed)
- **Claude Code** with Pro subscription
- **Python 3.8+** and **Go 1.21+** (for ProjectDiscovery tools)
- **API Keys:** `H1_API_TOKEN` (HackerOne), `GITHUB_TOKEN` (optional), `TELEGRAM_BOT_TOKEN` + `TELEGRAM_CHAT_ID` (optional)

---

## Disclaimer

**For authorized security testing only.** Only test targets within an approved bug bounty program scope. Never test systems without explicit permission. Follow responsible disclosure practices.

---

<div align="center">

**Built to hunt. 🎯**

</div>
