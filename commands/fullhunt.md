---
description: "Full autonomous bug bounty hunt — scope import → recon → rank → hunt → exploit → validate → dedup → report. Takes a domain and outputs HackerOne-ready vulnerability reports. Usage: /fullhunt target.com [--platform hackerone] [--program handle] [--mode balanced]"
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

## What This Does

Runs the COMPLETE bug bounty pipeline autonomously:

```
1. SCOPE       Import scope from HackerOne/Bugcrowd or accept manual domains
2. RECON       Subdomains, live hosts, URLs, JS analysis, tech fingerprinting
3. RANK        AI-prioritized attack surface (P1/P2/Kill)
4. HUNT        Active exploitation testing on every P1 endpoint:
                 → IDOR (ID swap, method swap, version rollback)
                 → Auth bypass (no auth, wrong auth, role escalation)
                 → SSRF (metadata, internal services, IP bypasses)
                 → Race conditions (parallel requests on financial endpoints)
                 → SQLi (error-based, time-based blind)
                 → SSTI (template engine detection → RCE)
                 → Business logic (price manipulation, workflow bypass)
                 → Header injection (CORS, Host, cache poisoning)
5. CHAIN       When bug A found → hunt for B and C (A→B→C exploit chains)
6. VERIFY      Prove exploitability with concrete PoC (real requests/responses)
7. VALIDATE    7-Question Gate — kill weak findings before wasting report time
8. DEDUP       Compare against HackerOne Hacktivity — avoid submitting duplicates
9. REPORT      Generate HackerOne-format reports with full PoC, CVSS, impact
```

## Model Routing (Pro Subscription Optimization)

| Phase | Model | Effort | Why |
|-------|-------|--------|-----|
| Scope import | Haiku | Low | Simple API parsing |
| Recon | Haiku | Low | Tool orchestration |
| Ranking | Haiku | Medium | Pattern matching |
| Hunting | Sonnet | High | Reasoning about vulns |
| Chain building | Sonnet | Max | Complex exploit logic |
| Validation | Sonnet | High | Gate evaluation |
| Report writing | Opus | High | Quality writing |

## Session Persistence

Hunt state is saved after every step to `hunt-memory/sessions/<target>_state.json`.

If you close Claude Code and reopen later:
- State is automatically loaded when you run `/fullhunt target.com` again
- Or use `/resume target.com` to see where you left off and continue

Saves: phase, scope, recon results, tested/untested endpoints, findings,
chains, validation results, reports generated, model usage.

## Autonomy

**This command runs 100% autonomously:**
- Claude makes ALL attack decisions — never asks the user
- Multiple attack vectors? Tests ALL of them in priority order
- If something fails, skips it and continues — never stops to ask
- You see output ONLY when findings are discovered or reports are generated

## Safety

- Every URL checked against scope before any request
- Every request logged to audit.jsonl
- Rate limited (2 req/sec testing, 10 req/sec recon)
- Circuit breaker on 5 consecutive 403/429/timeout
- Reports NEVER auto-submitted — review in `reports/` first
- Destructive methods (PUT/DELETE) are tested but with read-only verification first

## After /fullhunt

1. Review generated reports in `reports/<target>/`
2. Run `/validate` on any findings you want to double-check
3. Run `/compare` to check for duplicates before submitting
4. Submit manually on HackerOne/Bugcrowd
5. Run `/remember` to save successful patterns to hunt memory

## Requirements

- Kali Linux with Go tools installed (`./install_tools.sh`)
- Two test accounts on target (attacker + victim) for IDOR testing
- `interactsh-client` for OOB SSRF detection (installed by install_tools.sh)
- Optional: `H1_API_TOKEN` env var for HackerOne scope import
