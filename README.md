# 🎯 HunterAI

### Hypothesis-Driven AI Bug Bounty Engine for Claude Code

*Think like a hacker first. Then scale with AI.*

[![Claude Code](https://img.shields.io/badge/Claude_Code-Plugin-D97706.svg?style=flat-square&logo=anthropic&logoColor=white)](https://claude.ai)
[![Kali Linux](https://img.shields.io/badge/Kali_Linux-Ready-557C94.svg?style=flat-square&logo=kalilinux&logoColor=white)](https://kali.org)
[![Python 3.8+](https://img.shields.io/badge/Python-3.8+-3776AB.svg?style=flat-square&logo=python&logoColor=white)](https://python.org)
[![Tools](https://img.shields.io/badge/Tools-90+-green.svg?style=flat-square)](https://github.com/1fanya/hunterAI)
[![MCP](https://img.shields.io/badge/MCP-Burp_+_H1-blue.svg?style=flat-square)](https://github.com/1fanya/hunterAI)

---

## What makes this different

Most AI bug bounty tools are automated scanners — they run nuclei, sqlmap, dalfox against endpoints and hope something hits. HunterAI is built on a different principle: **understand the application first, then attack with hypotheses.**

There are two hunting modes:

**`/fullhunt`** — autonomous autopilot. Runs breadth-first across large scope. Finds low-hanging fruit: known CVEs, misconfigs, basic injection. Good for initial sweeps.

**`/guided-hunt`** — human-AI collaboration. You provide application intelligence (what the app does, where the money flows, your hypotheses). Claude tests them at scale with two authenticated accounts. This is where the $5,000–$50,000 bugs live.

```
# Autopilot: scan everything, find easy wins
/fullhunt rockstargames

# Guided: you think, AI tests
# 1. Browse the app, fill in app-intel.md with what you notice
# 2. Set up two accounts in auth-pair.json
/guided-hunt rockstargames
```

---

## Quick start

```bash
# Clone
git clone https://github.com/1fanya/hunterAI.git
cd hunterAI

# Install everything (tools, python deps, browser)
chmod +x setup_hunter.sh && ./setup_hunter.sh

# Configure API keys
cp .env.example .env
nano .env  # Fill in tokens (see API keys table below)

# Update nuclei templates (official + community collections)
bash scripts/update-nuclei-templates.sh

# Verify
bash tools/integration_test.sh

# Launch
export CLAUDE_CODE_SUBAGENT_MODEL="claude-sonnet-4-6"
claude --model sonnet --dangerously-skip-permissions
```

---

## Installation

### Prerequisites

| Requirement | Version | Notes |
|---|---|---|
| Kali Linux | 2024.1+ | WSL2 or native |
| Python | 3.8+ | Pre-installed on Kali |
| Go | 1.21+ | For ProjectDiscovery tools |
| Claude Code | Latest | `npm install -g @anthropic-ai/claude-code` |
| Claude Pro | Required | For autonomous hunting |

### Automated install

```bash
chmod +x setup_hunter.sh && ./setup_hunter.sh
```

Installs: subfinder, httpx, katana, nuclei, gau, subzy, sqlmap, ffuf, nmap, commix, dalfox, xsstrike, Playwright + Chromium, Python packages.

### API keys

```bash
cp .env.example .env
nano .env
```

| Variable | Source | Priority |
|---|---|---|
| `H1_API_TOKEN` | [hackerone.com/settings/api_token](https://hackerone.com/settings/api_token) | Required |
| `H1_API_USERNAME` | Same page | Required |
| `TELEGRAM_BOT_TOKEN` | [@BotFather](https://t.me/BotFather) | Recommended |
| `TELEGRAM_CHAT_ID` | [@userinfobot](https://t.me/userinfobot) | Recommended |
| `GITHUB_TOKEN` | [github.com/settings/tokens](https://github.com/settings/tokens) | Recommended |
| `SHODAN_API_KEY` | [account.shodan.io](https://account.shodan.io) | Recommended |
| `NVD_API_KEY` | [nvd.nist.gov/developers](https://nvd.nist.gov/developers/request-an-api-key) | Recommended |
| `INTERACTSH_URL` | [interactsh](https://github.com/projectdiscovery/interactsh) | Recommended |
| `BURP_API_URL` | Default: `http://127.0.0.1:1337` | Optional |
| `BURP_API_KEY` | Burp Suite REST API settings | Optional |

### Verify installation

```bash
# Quick: python tool imports
python3 tools/smoke_test.py

# Full: tools actually run, hooks configured, structure valid
bash tools/integration_test.sh
```

---

## Hunting modes

### `/fullhunt <program>` — Autopilot

Fully autonomous. Give it a HackerOne program handle, get reports out.

```
/fullhunt shopify
```

Pipeline:
```
Phase 0: Program intel (scope, bounty table)        → recon-agent (Haiku)
Phase 1: Recon (subdomains, live hosts, URLs)        → recon-agent (Haiku)
Phase 2: Analysis (JS, tech profiling)               → recon-agent (Haiku)
Phase 3: Ranking (P1/P2/Kill)                        → recon-ranker (Haiku)
Phase 3.5: Application Intelligence (understand app) → hunt-agent (Sonnet)
Phase 4: Hypothesis-driven hunting                   → hunt-agent (Sonnet)
Phase 5: Validation (7-Question Gate)                → validator (Sonnet)
Phase 6: Chain building                              → chain-builder (Sonnet)
Phase 7: Dedup check                                 → Haiku
Phase 8: Report writing                              → report-writer (Sonnet)
```

Best for: initial sweeps, large scope, programs you haven't explored manually.

### `/guided-hunt <target>` — Human + AI

You provide the brain. AI provides the scale.

**Step 1:** Browse the app manually. Register accounts. Click every button. Watch Burp.

**Step 2:** Write your observations in `hunt-memory/<target>/app-intel.md`:
```markdown
## What the app does
E-commerce platform for digital goods

## Most sensitive actions
Payment processing, password reset, data export

## Interesting endpoints I noticed
- GET /api/v2/orders/{id} — returns full order with PII
- POST /api/v2/billing/apply-coupon — no visible rate limit

## My hypotheses
- IDOR on /api/v2/orders/{id} — probably no ownership check
- Race condition on /apply-coupon — single-use coupon may be double-claimable

## Auth tokens (two accounts)
Account A (attacker): Cookie: session=abc123...
Account B (victim):   Cookie: session=xyz789...
```

**Step 3:** Set up auth pair:
```bash
python3 tools/auth_pair.py --init target_name
# Edit hunt-memory/<target>/auth-pair.json with real tokens
```

**Step 4:** Run:
```
/guided-hunt target_name
```

Claude reads your app-intel, tests each hypothesis with both accounts, logs results, then suggests additional hypotheses based on what it found.

Best for: deep testing, high-value programs, complex business logic.

---

## How it thinks

HunterAI prioritizes by **bounty value**, not OWASP number:

| Priority | Class | Typical payout | Why |
|---|---|---|---|
| 1 | IDOR / BOLA | $2,000–$15,000 | Highest ROI, most programs |
| 2 | Auth bypass / privilege escalation | $3,000–$20,000 | Account takeover |
| 3 | OAuth / SSO flaws | $2,000–$10,000 | Token theft, ATO |
| 4 | Business logic | $1,000–$50,000 | Unique, rarely duplicated |
| 5 | Race conditions | $1,000–$5,000 | Double-spend, bypasses |
| 6 | SSRF | $2,000–$10,000 | Internal access |
| 7 | SQL injection | $500–$5,000 | Classic but often duped |
| 8 | XSS (stored) | $500–$3,000 | Needs impact |
| ... | Known CVEs (nuclei) | $200–$1,000 | Run LAST, not first |

Every finding passes the **7-Question Validation Gate** before reporting. If it fails any question, it's killed — no borderline cases.

---

## Auto-memory system

HunterAI uses **infrastructure-level memory** that survives context resets and auto-compact. You don't need to manually save anything.

| Layer | What it stores | How it works |
|---|---|---|
| PostToolUse hook | Every Bash result | Shell script auto-appends to `state.observations[]` after every tool call |
| SessionStart hook | Recovery context | Reads hunt state on every session start and after auto-compact |
| hunt_state.py | Observations, dead ends, hypotheses, current endpoint, tested classes | Python persistence — extended with v2 fields, backward-compatible |
| hunt-vault/ | Cross-hunt patterns, WAF bypasses, working techniques | Markdown knowledge base — updated after successful bounties |

After auto-compact, Claude automatically recovers: target, phase, last 10 observations, dead ends, active hypotheses. No data loss.

### Nuclei templates

Auto-updated on every session start. Additional community collections via:
```bash
bash scripts/update-nuclei-templates.sh
```

Sources: official ProjectDiscovery (9000+), missing CVEs collection (weekly), community custom templates.

Smart usage: fingerprint tech stack first → run targeted templates → custom templates for confirmed findings. Never shotgun all 9000 templates at every host.

---

## Subagent model routing

Main session runs **Sonnet**. Recon subagents run **Haiku** (70% cheaper, same quality for tool orchestration).

| Agent | Model | Effort | Purpose |
|---|---|---|---|
| recon-agent | Haiku | Low | Subdomain + URL discovery |
| recon-ranker | Haiku | Low | Endpoint classification |
| hunt-agent | Sonnet | High | Active vulnerability testing |
| validator | Sonnet | High | 7-Question Gate |
| chain-builder | Sonnet | High | Exploit chain building |
| report-writer | Sonnet | High | HackerOne report generation |

```bash
# Recommended launch
export CLAUDE_CODE_SUBAGENT_MODEL="claude-sonnet-4-6"
claude --model sonnet --dangerously-skip-permissions
```

---

## Commands

| Command | Mode | What it does |
|---|---|---|
| `/fullhunt <program>` | Autopilot | Full autonomous hunt — scope to reports |
| `/guided-hunt <target>` | Guided | Hypothesis-driven hunt with your app-intel |
| `/resume <program>` | Both | Resume after rate limits or crash |
| `/recon <domain>` | Recon | Subdomain + URL discovery only |
| `/hunt <domain>` | Active | Vulnerability testing on ranked endpoints |
| `/validate` | Quality | 7-Question Gate on findings |
| `/report` | Output | HackerOne-ready report generation |
| `/compare` | Dedup | Check finding against Hacktivity |
| `/chain` | Escalation | A→B→C exploit chain building |
| `/methodology` | Reference | View the hunting methodology |
| `/monitor <domain>` | Passive | Background recon for new attack surface |

---

## MCP integrations

### HackerOne MCP

| Tool | Auth | Purpose |
|---|---|---|
| `search_disclosed_reports` | No | Search Hacktivity for dupes |
| `get_program_stats` | No | Bounty ranges, response SLAs |
| `get_program_policy` | No | Scope, rules, safe harbor |
| `get_my_reports` | Yes | Your submitted reports |
| `add_report_comment` | Yes | Comment on a report |
| `close_report` | Yes | Self-close a report |
| `get_program_scope_auth` | Yes | Detailed authenticated scope |

### Burp Suite MCP

| Tool | Purpose |
|---|---|
| `get_proxy_history` | Intercepted requests/responses |
| `search_proxy` | Search by URL, method, status |
| `get_sitemap` | Discovered URLs |
| `send_to_repeater` | Send crafted request |
| `start_active_scan` | Launch active scan |
| `get_scan_status` | Scan findings and progress |
| `get_issue_definitions` | Burp issue type reference |

Setup:
```bash
claude mcp add hackerone -- python3 mcp/hackerone-mcp/server.py
claude mcp add burp --env BURP_API_URL=http://127.0.0.1:1337 -- python3 mcp/burp-mcp-client/server.py
```

---

## Tools (90+)

### Core exploitation

| Tool | Attack |
|---|---|
| `auth_pair.py` | Two-session IDOR/BOLA testing with response diffing |
| `auth_tester.py` | Auth bypass (6 patterns) |
| `exploit_verifier.py` | PoC generation (IDOR/SSRF/SQLi/SSTI/race) |
| `jwt_tester.py` | None algo, alg confusion, kid injection, weak secret |
| `graphql_exploiter.py` | Introspection, node IDOR, mutation auth, batching |
| `oauth_tester.py` | redirect_uri bypass (9 techniques), state, scope escalation |
| `cors_tester.py` | Origin reflection, null origin, subdomain wildcard |
| `smuggling_tester.py` | CL.TE, TE.CL, TE.TE, HTTP/2 desync |
| `race_tester.py` | Parallel requests on critical actions |
| `ssti_scanner.py` | 6 template engines, polyglot detection |

### Intelligence

| Tool | Purpose |
|---|---|
| `js_analyzer.py` | JS source map deobfuscation + API endpoint extraction |
| `cve_engine.py` | Version → CVE → Exploit lookup (NVD + CISA KEV + ExploitDB) |
| `github_dorker.py` | Leaked secrets, .env files, credentials |
| `shodan_recon.py` | Passive port scan, exposed services |
| `payload_mutator.py` | 50+ WAF bypass mutation strategies |
| `telegram_notifier.py` | Real-time findings to your phone |
| `nuclei_templater.py` | Auto-generate nuclei YAML from confirmed findings |

### Infrastructure

| Tool | Purpose |
|---|---|
| `hunt_state.py` | Crash-proof session persistence with observations, dead ends, hypotheses |
| `auth_pair.py` | Two-account auth management for IDOR testing |
| `safe_http.py` | Global rate limiter (configurable via HUNT_RATE_LIMIT) |
| `scope_guard.py` | Scope enforcement + circuit breaker |
| `integration_test.sh` | Full system validation (tools + hooks + config) |

---

## Project structure

```
hunterAI/
├── CLAUDE.md                    # Core rules (40 lines — compact by design)
├── .claude/
│   ├── agents/                  # 6 subagents with model routing
│   ├── hooks/                   # PostToolUse logger + SessionStart recovery
│   └── settings.json            # Hooks config, permissions, env vars
│
├── skills/                      # Detailed knowledge (loaded on demand, not at startup)
│   ├── hunting/SKILL.md         # 24-class checklist, Phase 3.5, bounty-value priorities
│   ├── reporting/SKILL.md       # 7-Question Gate, report rules, CVSS
│   ├── recon/SKILL.md           # Tool chain, SecLists, smart nuclei usage
│   ├── tools-reference/SKILL.md # All 90+ tools, MCP integrations
│   ├── token-economy/SKILL.md   # Model routing, 12 token-saving rules
│   └── hacker-mindset/SKILL.md  # How to think like a hacker, not a scanner
│
├── commands/                    # Slash command definitions
│   ├── fullhunt.md              # /fullhunt — autopilot pipeline
│   ├── guided-hunt.md           # /guided-hunt — human+AI collaboration
│   ├── resume.md                # /resume — session restore
│   └── ...
│
├── tools/                       # 90+ Python tools
│   ├── hunt_state.py            # Persistence (v2: observations, dead_ends, hypotheses)
│   ├── auth_pair.py             # Two-account IDOR testing
│   ├── integration_test.sh      # Full system validation
│   └── ...
│
├── mcp/                         # MCP servers
│   ├── hackerone-mcp/           # 7 tools
│   └── burp-mcp-client/         # 7 tools
│
├── hunt-memory/                 # Runtime state (auto-managed, gitignored)
├── hunt-vault/                  # Cross-hunt knowledge base
│   ├── patterns/                # Working techniques, WAF bypasses
│   └── methodology/             # Lessons learned
│
├── scripts/
│   └── update-nuclei-templates.sh  # Official + community template updater
│
├── reports/                     # Generated reports (gitignored)
└── archived/                    # Unused code (agent.py, brain.py)
```

---

## Optional: Vault MCP for cross-hunt knowledge

```bash
claude mcp add-json hunt-vault '{"type":"stdio","command":"npx","args":["-y","@bitbonsai/mcpvault@latest","./hunt-vault"]}' --scope project
```

Lets Claude search your accumulated knowledge (techniques, bypasses, patterns) without loading entire files into context.

---

## Troubleshooting

| Problem | Fix |
|---|---|
| `ModuleNotFoundError` | `pip install --break-system-packages <module>` |
| Rate limits during hunt | `/resume <program>` — picks up exactly where it stopped |
| Context lost after compact | Automatic — SessionStart hook reloads state |
| Nuclei templates outdated | `bash scripts/update-nuclei-templates.sh` |
| Burp MCP can't connect | Burp must be running with `--rest-api` flag |
| H1 MCP auth fails | Check `H1_API_TOKEN` and `H1_API_USERNAME` in `.env` |
| Integration test fails | Run `bash tools/integration_test.sh` for specific failures |
| No IDOR results | Set up two accounts: `python3 tools/auth_pair.py --init <target>` |

---

## Disclaimer

**For authorized security testing only.**

- Only test targets within an approved bug bounty program scope
- Never test systems without explicit written permission
- Follow responsible disclosure practices
- You are solely responsible for how you use this tool

---

**Think first. Hunt smart. 🎯**

*90+ tools · 24 vulnerability classes · Hypothesis-driven · Dual-mode hunting · Auto-memory · Model-routed subagents*
