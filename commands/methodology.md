---
description: "Professional 7-phase bug bounty hunting methodology. Adapted from Jason Haddix TBHM + real-world hunter workflows. Fully autonomous — Claude executes every phase. Usage: integrated into /fullhunt pipeline"
---

# Hunting Methodology — 7-Phase Autonomous Pipeline

Based on Jason Haddix's Bug Hunter's Methodology (TBHM) + real-world practices.
Every phase runs autonomously inside `/fullhunt`.

## Phase 1: Scope & Intelligence (Haiku/min)

```
1. Read full program scope (in-scope domains, exclusions, bug class exclusions)
2. Import scope into scope_guard
3. Load hunt_intel — check if target was hunted before
4. Read 5+ disclosed H1 reports for this program (hacktivity_learner)
5. Identify crown jewels — what would hurt the company most?
```

**Output:** scope.json, intel strategy, attack priority ranking

## Phase 2: Wide Recon (Haiku/low)

```
1. Subdomain enumeration — subfinder + assetfinder + amass
2. Live host discovery — httpx (status, title, tech)
3. Port scanning — nmap top 1000 on key hosts
4. URL crawling — katana (depth 3)
5. JS file extraction — find .js files, extract endpoints
6. Wayback URLs — gau/waybackurls for historical endpoints
```

**Output:** subdomains.txt, live_hosts.txt, urls.txt, js_endpoints.txt

## Phase 3: Content Discovery & Fingerprinting (Haiku/low)

```
1. Tech stack fingerprinting — Wappalyzer patterns, headers, meta tags
2. WAF detection — waf_detector
3. Directory fuzzing — ffuf with custom wordlists
4. API endpoint discovery — api_discovery (Swagger/GraphQL/debug)
5. Git exposure check — git_recon
6. Subdomain takeover check — subdomain_takeover
```

**Output:** tech_stack.json, endpoints.json, directories.json

## Phase 4: Version Detection & CVE Hunting (Haiku→Sonnet)

**THIS IS THE NEW CVE ENGINE PHASE**

```
1. Extract all product/version pairs from:
   - HTTP Server headers (Apache/2.4.49, nginx/1.18.0)
   - X-Powered-By headers (PHP/7.4.3)
   - HTML meta generators (WordPress 5.8.1)
   - JavaScript library versions (jQuery 3.6.0)
   - API response headers
   - Nmap service detection output

2. For each product/version:
   a. CVE lookup via NVD API (cve_engine.py)
   b. Check CISA KEV (actively exploited = highest priority)
   c. Search ExploitDB (searchsploit --json)
   d. Search Metasploit modules (msf_adapter.py)

3. Prioritize by:
   - CISA KEV matches → CRITICAL (exploit exists in the wild)
   - CVSS >= 9.0 with exploit → CRITICAL
   - CVSS >= 7.0 with exploit → HIGH
   - CVSS >= 7.0 without exploit → MEDIUM (custom exploitation)

4. For exploitable CVEs:
   a. Run Metasploit check (non-destructive) → confirm vulnerability
   b. Copy ExploitDB PoC → adapt and test
   c. Generate curl-based PoC for the report
```

**Output:** cve_results.json, exploit_matches.json

## Phase 5: Vulnerability Hunting (Sonnet/high)

**Priority order (highest ROI first):**

```
Tier 1 — High Bounty, Low Competition:
  1. IDOR / Broken Object Level Auth (auth_tester, response_differ)
  2. Auth bypass / Privilege escalation
  3. Business logic flaws (business_logic)
  4. Race conditions (race_tester)
  5. OAuth / SSO flaws (oauth_tester)

Tier 2 — High Bounty, Medium Competition:
  6. SSRF (ssrf_engine)
  7. SQL injection (sqlmap, manual)
  8. JWT attacks (jwt_analyzer)
  9. GraphQL abuse (graphql_deep)
  10. API mass assignment / BFLA (api_security)

Tier 3 — Medium Bounty:
  11. XSS (stored > reflected > DOM) (blind_xss)
  12. SSTI (ssti_scanner)
  13. Cache poisoning (cache_poison)
  14. HTTP/2 smuggling (h2_smuggler)
  15. Host header attacks (host_header)

Tier 4 — Chain Components:
  16. Open redirect (chain to OAuth) (open_redirect)
  17. Path traversal / LFI (path_traversal)
  18. File upload bypass (file_upload)
  19. XXE (xxe_scanner)
  20. 2FA bypass (twofa_bypass)
```

**For each finding: auto-run validation gate (Phase 6) immediately.**

## Phase 6: Auto-Validation & Chain Building (Sonnet/medium)

```
1. Every potential finding → 7-Question Gate (rules/reporting.md)
2. Check never-submit list → auto-KILL if standalone
3. Verify proof requirements per vuln class
4. Attempt chain building (chain_engine):
   - Open redirect → OAuth token theft
   - XSS → account takeover
   - SSRF → cloud metadata
   - IDOR + privilege escalation
5. PASS → record finding + generate PoC
   KILL → log reason + move on
```

## Phase 7: Report Generation (Sonnet/high)

```
1. For each validated finding:
   a. Generate title using formula: [Class] in [Endpoint] allows [actor] to [impact]
   b. Write report using rules/reporting.md template
   c. Include copy-pasteable curl PoC
   d. Calculate CVSS 3.1 with vector string
   e. Include actual response data (not just status codes)
2. Save to findings/<target>/reports/
3. Record in hunt_intel for cross-hunt learning
4. Save hunt state as completed
```

## Key Principles

1. **Impact-first** — hunt where the money is
2. **Version→CVE→Exploit** — automate known vulnerability exploitation
3. **Validate everything** — no theoretical bugs
4. **Chain aggressively** — low-severity + low-severity = high-severity
5. **Save state always** — survive crashes, limits, restarts
