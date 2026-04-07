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

## Multi-Model Cost Routing (Pro Subscription — Quality First)

**Balance: save tokens on setup, spend tokens on hunting.**

| Task | Model | Effort | Rationale |
|------|-------|--------|-----------|
| Scope import, recon setup | Haiku | Low | Parsing, no reasoning |
| WAF detect, wordlists | Haiku | Low | Tool orchestration |
| API discovery, takeover scan | Haiku | Low | Tool runs, check output |
| **Active hunting (IDOR, SSRF, auth)** | **Sonnet** | **High** | **This finds bounties** |
| **Chain building** | **Sonnet** | **High** | **This multiplies bounties** |
| **JWT/OAuth/2FA analysis** | **Sonnet** | **High** | **Complex exploitation** |
| **PoC + Report writing** | **Sonnet** | **High** | **Quality = acceptance** |

Modes: `--mode cheap` / `--mode balanced` (default) / `--mode quality`

### Token-Saving Rules (during hunt)
1. Don't explain what you're about to do — just do it
2. Don't summarize tool output back to yourself
3. Batch independent tool calls in parallel
4. Use `hunt_state.py` to persist — don't rely on conversation context

## Session Persistence & Resume

**CRITICAL: Hunt state MUST survive limits/crashes/closes.**

### How It Works
- `hunt_state.py` saves ALL state to `hunt-memory/sessions/<target>_state.json`
- After every tool call: `state.complete_tool("tool_name")`
- After every finding: `state.add_finding({...})`
- State is saved automatically on every mutation

### Resume After Limits Hit
When user reopens Claude Code and types `/fullhunt target.com` or `/resume target.com`:
1. Load `HuntState("target.com")` from disk
2. Check `state.get_phase()` — if not "init", RESUME
3. Print `state.get_resumption_prompt()` — shows completed tools + findings
4. **Skip all completed tools** — `state.is_tool_completed("name")`
5. Continue from current phase

**NEVER re-run a completed tool. Pick up exactly where you stopped.**

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
| `/resume` | **Resume previous hunt** (crash-proof) |
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
| **report-writer** | HackerOne reports | Sonnet |
| **web3-auditor** | Smart contracts | Sonnet |

## Active Exploitation Tools (34+ tools in `tools/`)

### Core Exploitation
| Tool | Attack | Priority |
|---|---|---|
| `auth_tester.py` | IDOR + auth bypass (6 test patterns) | #1 ROI |
| `exploit_verifier.py` | Prove bugs with PoCs (IDOR/SSRF/SQLi/SSTI/race) | Critical |
| `jwt_tester.py` / `jwt_analyzer.py` | JWT none algo, alg confusion, kid injection, weak secret, claim tampering | High |
| `graphql_exploiter.py` / `graphql_deep.py` | Introspection, node IDOR, mutation auth, batching, DoS | High |
| `cors_tester.py` | Origin reflection, null origin, subdomain wildcard | High |
| `smuggling_tester.py` / `h2_smuggler.py` | CL.TE, TE.CL, TE.TE, HTTP/2 desync | High |
| `subdomain_takeover.py` | 15 service fingerprints, dangling CNAME detection | Medium |
| `cloud_enum.py` | S3/Azure/GCP/Firebase bucket enum + write test | Medium |
| `git_dorker.py` / `git_recon.py` | .git exposure, GitHub code search, 14 secret patterns | Medium |

### Advanced Hunting
| Tool | Attack | Priority |
|---|---|---|
| `scope_guard.py` / `safe_http.py` | Scope enforcement + circuit breaker + rate limiter | **CRITICAL** |
| `waf_detector.py` | Fingerprint WAF/CDN + per-WAF bypass payloads | **Pre-hunt** |
| `response_differ.py` | Semantic IDOR diffing (JSON field-level + PII detection) | #1 ROI |
| `session_manager.py` / `auth_manager.py` | Authenticated sessions (cookies, JWT, login flows) | Required |
| `param_miner.py` | Hidden parameter discovery via response diffing | High |
| `ws_tester.py` | WebSocket CSWSH, auth bypass, IDOR, injection | High |
| `api_discovery.py` | Swagger/OpenAPI/GraphQL/Postman/debug endpoint discovery | High |
| `ssti_scanner.py` | 6 template engines, polyglot detection, auto-RCE | High |
| `host_header.py` | Password reset poisoning, cache poison, SSRF via Host | High |
| `oauth_tester.py` | redirect_uri bypass (9 techniques), state, scope escalation | High |
| `blind_xss.py` | Callback-based blind XSS payloads + injection point discovery | Medium |
| `twofa_bypass.py` | Direct access, rate limit, response manipulation | Medium |

### Pipeline & Intelligence
| Tool | Purpose |
|---|---|
| `hunt_state.py` | **Crash-proof session persistence** (resume across restarts) |
| `hunt_intel.py` | Cross-hunt self-learning (tool success rates, strategy evolution) |
| `report_finalizer.py` | H1-quality report generation + individual submissions |
| `chain_engine.py` | Auto-escalation (10 chain rules, 3-20x multiplier) |
| `poc_generator.py` | Auto curl + Python + H1 report per finding |
| `smoke_test.py` | Full system validation |
| `monitor.py` | Attack surface change detection |

### External Tools (installed by `setup_hunter.sh`)

Recon: subfinder, httpx, katana, dnsx, naabu, assetfinder, waybackurls, gau, gospider
Scanning: nuclei, ffuf, feroxbuster, dalfox, crlfuzz, nmap, sqlmap
Fuzzing: arjun, paramspider, xsstrike
Analysis: gf, anew, qsreplace, trufflehog, commix
Takeover: subzy
OOB: interactsh-client
Wordlists: SecLists, GF patterns, nuclei templates

## Critical Rules (Always Active — from `rules/`)

> **See `rules/hunting.md` and `rules/reporting.md` for full details.**

### Non-Negotiable (auto-enforced during every hunt)

1. **READ FULL SCOPE** before touching any asset
2. **NO THEORETICAL BUGS** — "Can attacker do this RIGHT NOW?" If no → KILL
3. **VERIFY ENDPOINT IS REACHABLE** before recording any finding
4. **PROVE IMPACT WITH DATA** — not just status codes (see proof table in rules/hunting.md)
5. **AUTO-VALIDATE EVERY FINDING** — run 7-Question Gate before spending tokens on reports
6. **CHECK NEVER-SUBMIT LIST** — standalone header/introspection/self-XSS/redirect = auto-KILL
7. **TWO ACCOUNTS FOR IDOR** — attacker sees victim's data (not self-testing)
8. **5-MINUTE RULE** per endpoint — rotate if nothing
9. **SAVE STATE** after every tool — user may close anytime, `/resume` must work
10. **DON'T WASTE TOKENS** on recon parsing — save them for hunting and validation

### Report Quality (auto-enforced)

11. **NEVER say "could potentially"** — concrete statements only
12. **TITLE FORMULA**: `[Bug Class] in [Endpoint] allows [actor] to [impact]`
13. **COPY-PASTEABLE PoC** — curl command that reproduces the bug
14. **ACTUAL RESPONSE DATA** — not just "200 OK"
15. **UNDER 600 WORDS** — triagers skim
16. **CVSS 3.1 WITH VECTOR** — don't overclaim, don't underclaim
17. **SEPARATE BUGS = SEPARATE REPORTS** — independent bugs → separate payouts

### Pipeline Flow

```
HUNT → FIND potential vuln → AUTO-VALIDATE (7-Q Gate) → PASS? → REPORT
                                                      → KILL? → move on
```

**Never generate a report for a finding that hasn't passed validation.**

## Install on Kali Linux

```bash
git clone <repo>
cd hunterAI
chmod +x setup_hunter.sh && ./setup_hunter.sh

# Set env vars
export H1_API_TOKEN="your-token"
export GITHUB_TOKEN="your-token"          # optional
export HUNT_USERNAME="test@target.com"    # optional, for auth
export HUNT_PASSWORD="password123"         # optional
export INTERACTSH_URL="xxx.oast.fun"      # for blind SSRF/XSS

# Start hunting
/fullhunt target.com
```
