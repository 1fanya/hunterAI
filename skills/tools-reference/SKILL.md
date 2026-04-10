---
name: tools-reference
description: All tool tables — core exploitation, advanced hunting, CVE engine, elite recon, OSINT, pipeline tools, MCP integrations, external tools
---

## Core Exploitation Tools

| Tool | Attack | Priority |
|------|--------|----------|
| `auth_tester.py` | IDOR + auth bypass (6 test patterns) | #1 ROI |
| `exploit_verifier.py` | Prove bugs with PoCs (IDOR/SSRF/SQLi/SSTI/race) | Critical |
| `jwt_tester.py` / `jwt_analyzer.py` | JWT none algo, alg confusion, kid injection, weak secret, claim tampering | High |
| `graphql_exploiter.py` / `graphql_deep.py` | Introspection, node IDOR, mutation auth, batching, DoS | High |
| `cors_tester.py` | Origin reflection, null origin, subdomain wildcard | High |
| `smuggling_tester.py` / `h2_smuggler.py` | CL.TE, TE.CL, TE.TE, HTTP/2 desync | High |
| `subdomain_takeover.py` | 15 service fingerprints, dangling CNAME detection | Medium |
| `cloud_enum.py` | S3/Azure/GCP/Firebase bucket enum + write test | Medium |
| `git_dorker.py` / `git_recon.py` | .git exposure, GitHub code search, 14 secret patterns | Medium |

## Advanced Hunting Tools

| Tool | Attack | Priority |
|------|--------|----------|
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

## CVE & Exploit Engine

| Tool | Purpose |
|------|---------|
| `cve_engine.py` | **Version→CVE→Exploit lookup** (NVD + CISA KEV + ExploitDB + MSF) |
| `msf_adapter.py` | **Metasploit CLI adapter** (search/check/exploit via msfconsole) |

## Elite Recon & Analysis Tools

| Tool | Purpose |
|------|---------|
| `js_analyzer.py` | **JS source map deobfuscation** + API endpoint/secret/XSS sink extraction |
| `js_deps_scanner.py` | **JS library version → CVE lookup** (jQuery, lodash, Angular, React, etc.) |
| `cert_monitor.py` | **Certificate Transparency** subdomain monitor (crt.sh, tracks new subs) |
| `apk_analyzer.py` | **APK decompile** → extract endpoints, secrets, network configs |
| `nuclei_templater.py` | **Auto-generate nuclei YAML** from confirmed findings for reuse |
| `h1_api.py` | **HackerOne API** — scope import, Hacktivity dedup, bounty stats |
| `payload_mutator.py` | **WAF bypass engine** — 50+ XSS/SQLi/SSRF/LFI mutation strategies |
| `telegram_notifier.py` | **Real-time Telegram alerts** — findings, CVEs, hunt status |
| `multi_target.py` | **Multi-program queue** — priority hunting across multiple targets |
| `browser_auto.py` | **Playwright automation** — auth flows, screenshot PoCs, CSRF/OAuth tests |

## Intelligence & OSINT Tools

| Tool | Purpose |
|------|---------|
| `github_dorker.py` | **GitHub code search** — leaked secrets, .env files, endpoints, credentials |
| `shodan_recon.py` | **Shodan/InternetDB** — passive port scan, exposed services, vulns (no API key needed) |
| `wayback_analyzer.py` | **Wayback Machine** — find removed endpoints, old API versions, debug pages |
| `auto_scope.py` | **Auto-scope loader** — H1 program handle → scope config, zero-friction start |
| `recon_cron.py` | **Continuous recon** — background subdomain monitor + Telegram alerts on changes |

## Pipeline & Intelligence Tools

| Tool | Purpose |
|------|---------|
| `hunt_state.py` | **Crash-proof session persistence** (resume across restarts) |
| `hunt_intel.py` | Cross-hunt self-learning (tool success rates, strategy evolution) |
| `report_finalizer.py` | H1-quality report generation + individual submissions |
| `chain_engine.py` | Auto-escalation (10 chain rules, 3-20x multiplier) |
| `poc_generator.py` | Auto curl + Python + H1 report per finding |
| `smoke_test.py` | Full system validation |
| `monitor.py` | Attack surface change detection |

## External Tools (installed by `setup_hunter.sh`)

- **Recon**: subfinder, httpx, katana, dnsx, naabu, assetfinder, waybackurls, gau, gospider
- **Scanning**: nuclei, ffuf, feroxbuster, dalfox, crlfuzz, nmap, sqlmap
- **Fuzzing**: arjun, paramspider, xsstrike
- **Analysis**: gf, anew, qsreplace, trufflehog, commix
- **Takeover**: subzy
- **OOB**: interactsh-client
- **Exploit**: msfconsole, searchsploit

## MCP Integrations

### HackerOne MCP (`mcp/hackerone-mcp/server.py`)

| Tool | Auth | Purpose |
|------|------|---------|
| `search_disclosed_reports` | No | Search Hacktivity for dupes/intel |
| `get_program_stats` | No | Bounty ranges, response times |
| `get_program_policy` | No | Scope, rules, safe harbor |
| `get_my_reports` | Yes | List your submitted reports + status |
| `add_report_comment` | Yes | Comment on a report |
| `close_report` | Yes | Self-close a report |
| `get_program_scope_auth` | Yes | Detailed authenticated scope |

### Burp Suite MCP (`mcp/burp-mcp-client/server.py`)

| Tool | Purpose |
|------|---------|
| `get_proxy_history` | Fetch intercepted requests/responses |
| `search_proxy` | Search history by URL/method/status |
| `get_sitemap` | Discovered URLs from Burp sitemap |
| `send_to_repeater` | Send crafted request to Repeater |
| `start_active_scan` | Launch active scan on a URL |
| `get_scan_status` | Scan findings and progress |
| `get_issue_definitions` | Burp issue type reference |

### MCP Setup
```bash
chmod +x mcp/setup_mcp.sh && ./mcp/setup_mcp.sh
# Or manually: claude mcp add hackerone -- python3 mcp/hackerone-mcp/server.py
```
