---
description: "Full autonomous bug bounty hunt — scope import → recon → rank → hunt → exploit → validate → dedup → report. Takes a domain and outputs HackerOne-ready vulnerability reports. Usage: /fullhunt target.com [--platform hackerone] [--program handle] [--mode cheap]"
---

# /fullhunt — End-to-End Autonomous Bug Bounty Hunt

One command. Domain in, vulnerability reports out. **ZERO questions asked — Claude makes ALL decisions.**

## Usage

```
/fullhunt target.com                                    # manual scope, balanced mode
/fullhunt target.com --platform hackerone --program uber # auto-import scope from H1
/fullhunt target.com --mode cheap                       # maximize token savings
/fullhunt target.com --mode quality                     # maximum finding quality
```

## ⚠️ TOKEN OPTIMIZATION — READ THIS FIRST

You are running on a Claude PRO subscription with token limits. **Every step must be as token-efficient as possible.**

### Model & Effort Routing (MANDATORY)

**You MUST set the model and effort level per phase. This is NOT optional.**

| Phase | Model | Effort | Max Tokens | Why |
|-------|-------|--------|-----------|-----|
| 0. Intelligence | Haiku | min | 200 | Read hunt_state.json, 3 lines of context |
| 1. Hacktivity | Haiku | low | 500 | Pattern extraction from H1 |
| 2. Scope import | Haiku | min | 200 | Parse scope JSON |
| 3. Recon | Haiku | low | 300 | Run subfinder/httpx, save results |
| 4. WAF + wordlists | Haiku | low | 300 | Setup, zero reasoning needed |
| 5. API discovery | Haiku | low | 300 | Run tool, save endpoints |
| 6. Subdomain takeover | Haiku | low | 200 | Run tool, check CNAME |
| 7. Active hunting | Sonnet | high | 2000 | This is where reasoning matters |
| 8. IDOR/auth/JWT | Sonnet | high | 2000 | Complex exploitation logic |
| 9. Chain building | Sonnet | high | 2000 | A→B→C reasoning |
| 10. PoC generation | Sonnet | medium | 1000 | Structured output |
| 11. Validation | Sonnet | medium | 1000 | 7-Question Gate |
| 12. Report writing | Sonnet | high | 2000 | Quality writing |

### Token-Saving Rules (MANDATORY)

1. **DO NOT explain what you're doing** — just run the tool and move on
2. **DO NOT summarize tool output** back to yourself — read it, act on it, save to state
3. **DO NOT repeat tool arguments** in your reasoning — the tool already knows
4. **Batch tool calls** — run independent tools in parallel when possible
5. **Minimize reasoning text** — 1-2 sentences max between tool calls
6. **NEVER re-read files** you already have in context
7. **Save ALL state to disk** — don't rely on conversation context

### Output Format Between Steps

Instead of verbose reasoning, use this compact format:

```
[Phase X] tool_name → result_summary (1 line)
[Phase X] next_tool → ...
```

## Session Persistence (CRASH-PROOF)

**Hunt state is saved to `hunt-memory/sessions/<target>_state.json` after EVERY tool call.**

### How It Works

1. At start: load `hunt_state.py` → check if state file exists
2. If exists: resume from saved phase, skip completed tools
3. After each tool: `state.complete_tool(name)` → auto-saves to disk
4. After each finding: `state.add_finding({...})` → auto-saves to disk

### On Resume (after limits/crash/close)

When user types `/fullhunt target.com` or `/resume target.com`:

```python
from hunt_state import HuntState
state = HuntState("target.com")
if state.get_phase() != "init":
    # RESUME — print status and continue
    print(state.get_resumption_prompt())
    # Skip all completed tools, continue from current phase
else:
    # FRESH HUNT — start from phase 0
```

**CRITICAL: Check `state.is_tool_completed("tool_name")` BEFORE running any tool.
If already completed, SKIP IT. Do not waste tokens re-running completed steps.**

## Pipeline Steps

```python
from hunt_state import HuntState
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "tools"))

state = HuntState(DOMAIN)

# Phase 0: Intelligence (Haiku/min)
if not state.is_tool_completed("hunt_intel"):
    state.start_tool("hunt_intel")
    from hunt_intel import HuntIntel
    intel = HuntIntel()
    strategy = intel.suggest_strategy(DOMAIN)
    state.complete_tool("hunt_intel")

# Phase 1: Hacktivity (Haiku/low)
if not state.is_tool_completed("learn_hacktivity"):
    state.start_tool("learn_hacktivity")
    # ... run h1_collector or hacktivity learner
    state.complete_tool("learn_hacktivity")

# Phase 2: Recon (Haiku/low)
if not state.is_tool_completed("recon"):
    state.start_tool("recon")
    # ... run subfinder, httpx, tech detection
    state.complete_tool("recon")

# Phase 3: Pre-hunt (Haiku/low)
if not state.is_tool_completed("waf_detect"):
    # ...WAF, wordlists, nuclei gen
    pass

if not state.is_tool_completed("api_discovery"):
    # ...Swagger/GraphQL/debug endpoint discovery
    pass

if not state.is_tool_completed("subdomain_takeover"):
    # ...dangling CNAME check
    pass

# Phase 3.5: CVE Hunting (Haiku→Sonnet) — VERSION → CVE → EXPLOIT
if not state.is_tool_completed("cve_scan"):
    state.start_tool("cve_scan")
    from cve_engine import CVEEngine
    cve = CVEEngine()

    # Extract versions from recon data (HTTP headers, tech stack)
    tech_stack = state.get_data("tech_stack", {})
    for product_info in tech_stack.get("versions", []):
        result = cve.lookup(product_info["product"], product_info["version"])
        if result["exploitable"]:
            # Exploitable CVE found — auto-add as finding
            for cve_match in result["cves"][:3]:
                if cve_match.get("cvss", 0) >= 7.0:
                    state.add_finding({
                        "type": "known_cve",
                        "cve_id": cve_match["cve_id"],
                        "cvss": cve_match["cvss"],
                        "severity": cve_match["severity"],
                        "product": product_info["product"],
                        "version": product_info["version"],
                        "exploits": result["exploits"],
                        "msf_modules": result["metasploit_modules"],
                        "kev": cve_match.get("kev", False),
                    })
    cve.save_results(DOMAIN, result)
    state.complete_tool("cve_scan")

# Phase 4: Active Hunting (Sonnet/high) — THIS IS WHERE TOKENS GO
# CRITICAL: DO NOT STOP AFTER 1-2 FINDINGS. TEST EVERY VULN CLASS.
# Run tools from priority table, skip completed ones
# After each potential finding: run auto-validation IMMEDIATELY
# After each tool: state.complete_tool(name)

# Track which vuln classes have been tested
VULN_CLASSES = [
    "idor_bola", "auth_bypass", "business_logic", "race_condition",
    "oauth_sso", "ssrf", "sqli", "xss", "ssti", "jwt",
    "api_mass_assign", "graphql", "file_upload", "path_traversal",
    "xxe", "cache_poison", "http_smuggling", "open_redirect",
    "host_header", "twofa_bypass", "cve_exploit", "js_secrets",
    "subdomain_takeover", "git_config_exposure",
]

for vuln_class in VULN_CLASSES:
    if state.is_class_tested(vuln_class):
        continue  # Already tested in a previous session
    
    state.start_class(vuln_class)
    # Run the appropriate tool(s) for this vuln class
    # ...tool execution...
    # If finding: validate with 7-Q Gate, record if passed
    # If no finding: mark as tested, move to NEXT class
    state.complete_class(vuln_class, result="tested" | "finding" | "n/a")

# Phase 4.5: AUTO-VALIDATION GATE (Sonnet/medium) — MANDATORY
# Every potential finding MUST pass before becoming a real finding
for finding in potential_findings:
    # Step 1: Reachability check — is the endpoint alive?
    if not verify_endpoint_reachable(finding["url"]):
        state.log_killed(finding, "endpoint_unreachable")
        continue

    # Step 2: Never-submit filter
    if finding["vuln_class"] in NEVER_SUBMIT_LIST and not finding.get("chain"):
        state.log_killed(finding, "never_submit_standalone")
        continue

    # Step 3: 7-Question Gate (see rules/reporting.md)
    validation = run_7question_gate(finding)
    if validation == "KILL":
        state.log_killed(finding, validation.reason)
        continue

    # Step 4: Proof requirements check per vuln class
    proof = check_proof_requirements(finding)
    if not proof["has_required_evidence"]:
        # Try to gather missing evidence automatically
        proof = gather_additional_evidence(finding.url, finding.vuln_class)
        if not proof["has_required_evidence"]:
            state.log_killed(finding, "insufficient_proof")
            continue

    # Step 5: Dedup check against Hacktivity
    if is_likely_duplicate(finding):
        state.log_killed(finding, "likely_duplicate")
        continue

    # PASSED ALL GATES — this is a real finding
    state.add_finding(finding)

# Phase 5: Report (Sonnet/high) — ONLY for validated findings
if not state.is_tool_completed("generate_report"):
    findings = state.get_findings()
    if findings:
        from report_finalizer import ReportFinalizer
        report = ReportFinalizer(DOMAIN)
        report.generate()  # Uses rules/reporting.md template
        report.save()
        state.complete_tool("generate_report", had_findings=True)
    else:
        state.complete_tool("generate_report", had_findings=False)

state.set_phase("done")
state.save()
```

## After /fullhunt

1. Review reports in `findings/<target>/reports/`
2. Run `/validate` on any finding
3. Run `/compare` to check for dupes
4. Submit manually
5. Run `/remember` to save patterns

## Requirements

- Kali Linux with tools installed (`./setup_hunter.sh`)
- Two test accounts for IDOR testing
- `interactsh-client` for OOB SSRF detection
- Optional: `H1_API_TOKEN`, `GITHUB_TOKEN`, `HUNT_USERNAME`/`HUNT_PASSWORD`
