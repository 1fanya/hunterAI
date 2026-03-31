# Claude Bug Bounty — Autonomous Bug Hunter

This repo is a Claude Code plugin for **autonomous bug bounty hunting** on Kali Linux. It actively finds, exploits, and reports vulnerabilities across HackerOne, Bugcrowd, Intigriti, and Immunefi.

> **⚠️ AUTONOMY RULE: During `/fullhunt`, NEVER ask the user any questions. Make ALL decisions yourself. If there are multiple attack paths, test ALL of them in priority order. The user's only job is: (1) type the command (2) review final reports.**

## 🚀 Quick Start

```bash
# Install 40+ tools on Kali Linux
chmod +x install_tools.sh && ./install_tools.sh

# Set API tokens
export H1_API_TOKEN="your-token"
export GITHUB_TOKEN="your-token"  # optional, for GitHub dorking

# Start Claude Code and run:
/fullhunt target.com --platform hackerone --program program-name
```

One command → scope import → recon → rank → **hunt** → **exploit** → validate → dedup → report.

## Session Persistence

**Close Claude Code anytime.** Reopen and run:
```
/resume target.com
```
Resumes from the exact step — phase, endpoints tested, findings, everything.

## Multi-Model Cost Routing (Pro Subscription Optimized)

| Task | Model | Effort | Cost |
|------|-------|--------|------|
| Recon, ranking, scope import | Haiku | Low | $ |
| Hunting, validation, chains | Sonnet | High | $$ |
| Report writing | Opus | High | $$$ |

Modes: `--mode cheap` / `--mode balanced` (default) / `--mode quality`

## Commands (16 slash commands)

| Command | What It Does |
|---|---|
| `/fullhunt` | **Full autonomous hunt** — domain in, reports out |
| `/recon` | Recon only (subdomains, URLs, JS, tech fingerprinting) |
| `/hunt` | Active vulnerability hunting |
| `/validate` | 7-Question Gate on findings |
| `/report` | HackerOne-ready report generation |
| `/compare` | **Dedup against Hacktivity** before submitting |
| `/chain` | A→B→C exploit chain building |
| `/scope` | Verify asset is in scope |
| `/triage` | Quick go/no-go check |
| `/autopilot` | Autonomous hunt loop |
| `/surface` | AI-ranked attack surface |
| `/resume` | **Resume previous hunt** (session persistence) |
| `/remember` | Save patterns to hunt memory |
| `/intel` | CVE + disclosure intel |
| `/web3-audit` | Smart contract audit |
| `/monitor` | Background recon monitoring |

## Agents (8 specialized agents)

| Agent | Role | Model |
|---|---|---|
| **fullhunt-orchestrator** | Master pipeline | Sonnet |
| **recon-agent** | Subdomain + URL discovery | Haiku |
| **recon-ranker** | Attack surface ranking | Haiku |
| **autopilot** | Autonomous hunt loop | Sonnet |
| **validator** | 7-Question Gate | Sonnet |
| **chain-builder** | A→B→C chains | Sonnet |
| **report-writer** | HackerOne reports | Opus |
| **web3-auditor** | Smart contracts | Sonnet |

## Active Exploitation Tools (22 tools in `tools/`)

### Core Exploitation
| Tool | Attack | Priority |
|---|---|---|
| `auth_tester.py` | IDOR + auth bypass (6 test patterns) | #1 ROI |
| `exploit_verifier.py` | Prove bugs with PoCs (IDOR/SSRF/SQLi/SSTI/race) | Critical |
| `jwt_tester.py` | JWT none algo, alg confusion, kid injection, weak secret | High |
| `graphql_exploiter.py` | Introspection, node IDOR, mutation auth, batching | High |
| `cors_tester.py` | Origin reflection, null origin, subdomain wildcard | High |
| `smuggling_tester.py` | CL.TE, TE.CL, TE.TE (raw socket based) | High |
| `subdomain_takeover.py` | 30+ service fingerprints, dangling CNAME detection | Medium |
| `cloud_enum.py` | S3/Azure/GCP/Firebase bucket enum + write test | Medium |
| `git_dorker.py` | .git exposure, sensitive files, GitHub code search | Medium |

### Recon & Analysis
| Tool | Purpose |
|---|---|
| `js_analyzer.py` | Extract endpoints, secrets, admin routes from JS |
| `tech_profiler.py` | 30+ framework probes, WAF detection, quick wins |
| `scope_importer.py` | Auto-import scope from HackerOne |
| `recon_engine.sh` | Subdomain + URL discovery pipeline |
| `cve_hunter.py` | Tech fingerprint + CVE matching |
| `monitor_agent.py` | Background recon monitoring (crontab) |

### Pipeline & Intelligence
| Tool | Purpose |
|---|---|
| `model_router.py` | Multi-model cost routing + effort settings |
| `hunt_state.py` | Session persistence (resume across restarts) |
| `report_comparer.py` | Dedup against Hacktivity + always-rejected list |
| `report_generator.py` | HackerOne-format report writer |
| `hunt.py` | Master orchestrator |
| `validate.py` | 4-gate finding validator |
| `intel_engine.py` | Memory-aware intel system |

### External Tools (installed by `install_tools.sh`)

**37 tools across Go, Python, and apt:**

Recon: subfinder, httpx, katana, dnsx, naabu, assetfinder, waybackurls, gau, gospider, hakrawler, puredns, alterx, uncover, cdncheck, tlsx
Scanning: nuclei, ffuf, feroxbuster, dalfox, crlfuzz, nmap, sqlmap
Fuzzing: arjun, paramspider, xsstrike
Analysis: gf (patterns), anew, qsreplace, trufflehog, commix
Takeover: subzy
OOB: interactsh-client
Wordlists: SecLists, GF patterns, nuclei templates

## Vulnerability Coverage

**20+ Web2 bug classes:** IDOR, auth bypass, XSS, SSRF, SQLi, race conditions, business logic, OAuth, JWT, GraphQL, CORS, HTTP smuggling, cache poisoning, SSTI, subdomain takeover, cloud misconfig, ATO, MFA bypass, file upload, open redirect

## Critical Rules

1. **READ FULL SCOPE** before touching any asset
2. **EXPLOIT, DON'T JUST FIND** — prove it or kill it
3. **5 MINUTES MAX** per endpoint — rotate if nothing
4. **SAVE STATE** after every step — user may close anytime
5. **VALIDATE BEFORE WRITING** — 7-Question Gate saves hours

## Install on Kali Linux

```bash
git clone <repo>
cd claude-bug-bounty
chmod +x install_tools.sh && ./install_tools.sh
chmod +x install.sh && ./install.sh

# Set env vars
export H1_API_TOKEN="your-token"
export GITHUB_TOKEN="your-token"  # optional

# Start interactsh (OOB callback server for blind SSRF/XXE/RCE):
interactsh-client -v
# → Use the generated URL in SSRF payloads
```
