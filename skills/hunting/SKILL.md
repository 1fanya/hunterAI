---
name: hunting
description: Exhaustive hunting methodology — Phase 3.5 app intelligence, hypothesis-driven testing, 24 vuln class checklist (bounty-value order), pipeline flow
---

## Phase 3.5: Application Intelligence (MANDATORY before hunting)

Before running ANY security tool, you must understand the target as a USER first.

### Step 1: Manual app walkthrough
Register an account (or two). Browse every page. Click every button.
Use Burp proxy or browser dev tools to capture all API calls.
Answer these questions IN WRITING to `hunt-memory/<target>/app-intel.md`:

1. **What does this app do?** (e-commerce, SaaS, social, fintech, etc.)
2. **What is the most sensitive action?** (payment, password reset, data export, admin action)
3. **What data is most valuable?** (PII, financial data, credentials, private content)
4. **What are the trust boundaries?** (user vs admin, free vs paid, tenant A vs tenant B)
5. **What are the money flows?** (purchases, refunds, credits, subscriptions)
6. **What third-party integrations exist?** (OAuth providers, payment processors, webhooks)
7. **What is the API structure?** (REST with /api/v1/resource/{id}, GraphQL, legacy endpoints)
8. **Where are the ID parameters?** (every place a user-controlled ID determines what data is returned)

### Step 2: Attack surface mapping (from app understanding, not from tools)
Based on Step 1, create a PRIORITIZED attack plan in `hunt-memory/<target>/attack-plan.md`:

DO NOT prioritize by OWASP category. Prioritize by BOUNTY VALUE:

**Priority 1 — Account takeover paths:**
- OAuth/SSO: state parameter, redirect_uri manipulation, token leakage
- Password reset: host header injection, token predictability, flow bypass
- Session: fixation, JWT weaknesses, cookie scope
- 2FA: bypass via direct endpoint access, rate limiting, response manipulation

**Priority 2 — Data access control:**
- IDOR: every endpoint with an ID parameter, test with second account
- BOLA: object-level authorization on ALL CRUD operations
- Tenant isolation: can user A see user B's data?
- Role escalation: can regular user hit admin endpoints?

**Priority 3 — Business logic:**
- Price/quantity manipulation (negative values, zero, overflow)
- Flow bypass (skip payment step, skip verification)
- Race conditions on critical operations (double-spend, double-claim)
- Coupon/credit abuse

**Priority 4 — Injection (only after 1-3 are exhausted):**
- SSRF in URL inputs, file imports, webhooks
- SQLi/XSS/SSTI where user input hits dangerous sinks

**Priority 5 — Known CVEs (run nuclei LAST, not first):**
- Only relevant after tech stack is fingerprinted
- Custom templates based on actual tech found, not shotgun scan

### Step 3: Hypothesis-driven hunting
For each priority item, write a HYPOTHESIS before testing:

> "I believe /api/v2/orders/{id} is vulnerable to IDOR because the GET request returns order data and the only authorization check is the session cookie, with no ownership validation on the order ID."

Then TEST the hypothesis. If it fails, log it as a dead end with WHY it failed.
If it succeeds, immediately validate (7-Question Gate) and write the report.

**DO NOT run tools without a hypothesis.** "Let me try sqlmap on every parameter" is not a hypothesis. "The search parameter on /products?q= reflects user input in the response without encoding, which may allow reflected XSS" IS a hypothesis.

---

## IDOR Testing — Always Use auth_pair.py

Never test IDOR with a single session — it proves nothing.

```python
from auth_pair import AuthPair
pair = AuthPair.load("target")            # loads hunt-memory/target/auth-pair.json
result = pair.test_idor("/api/v2/orders/VICTIM_ORDER_ID")
if result["idor_likely"]:
    print(pair.diff_responses(...))       # compare attacker vs victim responses
    # proceed to 7-Question Gate
```

If `auth-pair.json` doesn't exist, tell the human:
```bash
python3 tools/auth_pair.py --init target   # creates template, fill in session tokens
```

**Rule: No auth pair = no IDOR testing. Create it before this phase.**

---

## Exhaustive Hunting — 24 Vuln Class Checklist (Bounty-Value Order)

> **MANDATORY: Every `/fullhunt` MUST test ALL of these before generating a final report.**
> **Finding bugs early does NOT mean you stop. Keep going until every box is checked.**

```
[ ] 1.  IDOR / BOLA              — highest ROI in bug bounty; every ID param, 2nd account
[ ] 2.  Auth bypass               — direct URL access, role escalation, privilege escalation
[ ] 3.  OAuth/SSO flaws           — state, redirect_uri bypass, token leakage, flow hijack
[ ] 4.  Business logic            — price manipulation, flow skip, negative values, coupon abuse
[ ] 5.  Race conditions           — parallel requests on critical actions (double-spend, double-claim)
[ ] 6.  SSRF                      — URL params, webhook inputs, file imports, redirects
[ ] 7.  SQL injection             — all user inputs, headers, cookies
[ ] 8.  XSS (stored/reflected)    — all input fields, URL params, file upload names
[ ] 9.  JWT attacks               — none/HS256, key confusion, kid injection, expired tokens
[ ] 10. 2FA bypass                — direct access, rate limit, response tamper
[ ] 11. SSTI                      — template expressions in user input
[ ] 12. API mass assignment       — extra params in POST/PUT bodies
[ ] 13. GraphQL abuse             — introspection, batch queries, auth bypass
[ ] 14. File upload               — extension bypass, content-type, web shells
[ ] 15. Path traversal / LFI      — file read params, download endpoints
[ ] 16. XXE                       — XML upload, SOAP endpoints
[ ] 17. Host header attacks       — password reset poisoning, routing
[ ] 18. Cache poisoning           — unkeyed headers, host override
[ ] 19. HTTP smuggling            — CL.TE, TE.CL on load balancers
[ ] 20. Open redirect             — login redirects, OAuth, link params (for chains only)
[ ] 21. CVE exploitation          — version fingerprint → cve_engine → exploit
[ ] 22. JS secrets/source maps    — js_analyzer + js_deps_scanner
[ ] 23. Subdomain takeover        — dangling CNAMEs
[ ] 24. Git/config exposure       — .git, .env, debug endpoints
```

**After EVERY finding, mark it and KEEP GOING to the next unchecked class.**
**Only generate the final report when ALL 24 classes have been tested or confirmed N/A.**

## Pipeline Flow

```
Phase 3.5: App Intelligence → write app-intel.md + attack-plan.md
     ↓
HYPOTHESIS → test vuln class → FIND? → validate (7-Q Gate) → PASS? → record finding
                                                            → KILL? → log + move on
           → no find? → log dead end → mark class as tested → NEXT CLASS
           → ALL 24 classes tested? → GENERATE FINAL REPORT
```

**Never run a tool without a hypothesis. Never stop after 1-2 bugs. Test everything.**
**Never generate a report for a finding that hasn't passed validation.**

## Critical Hunting Rules

- **5-MINUTE RULE** per endpoint — rotate if nothing found after 5 minutes
- **TWO ACCOUNTS FOR IDOR** — attacker must see victim's data (never self-testing)
- **VERIFY ENDPOINT IS REACHABLE** before recording any finding
- **PROVE IMPACT WITH DATA** — not just status codes
- **AUTO-VALIDATE EVERY FINDING** — run 7-Question Gate before spending tokens on reports
- **CHECK NEVER-SUBMIT LIST** — standalone header/introspection/self-XSS/redirect = auto-KILL
- **DEDUP-FIRST** — check Hacktivity before deep testing a vuln class

## Token Budget Allocation Per Hunt

```
Total budget = 100%
├── 5%  — Phase 0-1: Scope + Program intel (Haiku)
├── 5%  — Phase 2: Recon (Haiku — external tools do the work)
├── 5%  — Phase 2.5: Pre-hunt intel (Haiku — tool orchestration only)
├── 5%  — Phase 3: Ranking (Haiku — one-shot classification)
├── 10% — Phase 3.5: Application Intelligence (Sonnet — understand the app)
├── 45% — Phase 4: Hypothesis-driven hunting (Sonnet — THIS IS WHERE BOUNTIES ARE)
├── 15% — Phase 5: Validation + chains (Sonnet — quality matters)
├── 5%  — Phase 6: Dedup check (Haiku — API calls)
└── 5%  — Phase 7: Report writing (Sonnet — quality = acceptance)
```
