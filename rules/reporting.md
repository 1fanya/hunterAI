---
description: Always-active reporting rules. Auto-enforced during report generation — never submit a report that violates these.
---

# Reporting Rules (Always Active)

## 1. NEVER USE THEORETICAL LANGUAGE

```
BANNED: "could potentially allow"
BANNED: "may allow an attacker to"
BANNED: "might be possible"
BANNED: "could lead to"
BANNED: "could be chained with X to cause Y" (unless chain is PROVEN)

REQUIRED: "An attacker can [exact action] by [exact method]"
```

If you can't write a concrete statement → you don't have a bug yet. KILL IT.

## 2. AUTO-VALIDATE BEFORE WRITING (7-Question Gate)

Every finding MUST pass ALL 7 questions autonomously. ONE fail = KILL.

### Q1: Can I demonstrate this step-by-step RIGHT NOW?
```
1. Setup:   I need [account type / no account]
2. Request: [exact HTTP method, URL, headers, body]
3. Result:  Response shows [exact data / action completed]
4. Impact:  Real consequence is [ATO / PII exposed / money stolen]
```
If step 2 is "I need to investigate more" → KILL IT.

### Q2: Is the impact accepted by this program?
Check program scope. Is this bug class listed? Is it excluded?

### Q3: Is the vulnerable asset in scope?
Exact domain in scope? Not staging/dev? Not third-party?

### Q4: Does it need admin/privileged access an attacker can't get?
"Admin can do X" → KILL IT.
"Regular user can do X that only admin should" → valid.

### Q5: Is this known or documented behavior?
Search disclosed H1 reports + changelog + API docs.

### Q6: Can I prove impact beyond "technically possible"?
- IDOR → actual victim data in response (not just 200 OK)
- XSS → actual cookie in exfil request (not just alert())
- SSRF → internal service response body (not just DNS)
- OAuth → silent redirect with code (no consent screen)

### Q7: Is this on the never-submit list?
If yes and no chain → KILL IT immediately.

## 3. 4-GATE PRE-SUBMISSION CHECK (auto-run)

**Gate 0 (auto — 30 sec):**
- [ ] Confirmed with real HTTP requests (not code reading)
- [ ] Asset is in scope
- [ ] Reproducible from scratch
- [ ] Evidence captured (request + response)

**Gate 1 — Impact (auto — 2 min):**
- [ ] Can state what attacker walks away with
- [ ] More than "sees non-sensitive data"
- [ ] Real victim exists
- [ ] No unlikely preconditions

**Gate 2 — Dedup (auto — 5 min):**
- [ ] Searched H1 Hacktivity for endpoint + bug class
- [ ] Not in changelog as known issue
- [ ] Not documented behavior

**Gate 3 — Report quality (auto — 10 min):**
- [ ] Title follows formula
- [ ] Steps have exact HTTP request
- [ ] Evidence shows actual impact data
- [ ] CVSS calculated
- [ ] Fix recommendation included

## 4. TITLE FORMULA — NEVER DEVIATE

```
[Bug Class] in [Exact Endpoint] allows [actor] to [impact] [scope]
```

Good:
```
IDOR in /api/v2/invoices/{id} allows authenticated user to read any customer's invoice
Missing auth on POST /api/admin/users allows unauthenticated creation of admin accounts
OAuth Missing State in /connect/authorize allows attacker to perform account linking CSRF
```

Bad (never use):
```
IDOR vulnerability found
Security issue in API
Possible XSS
```

## 5. PROOF OF CONCEPT REQUIREMENTS

Every report MUST include:
1. **Copy-pasteable curl command** that reproduces the bug
2. **Actual response showing impact** (not just status code)
3. **Two accounts used** for IDOR (attacker + victim)
4. **Screenshot-equivalent evidence** (request + response pairs)

```bash
# Example PoC format:
# Step 1: Get victim's data as attacker
curl -s -H "Authorization: Bearer ATTACKER_TOKEN" \
  "https://api.target.com/users/VICTIM_ID/profile"

# Response (victim's private data returned to attacker):
# {"name":"victim_user","email":"victim@email.com","ssn":"123-45-6789"}
```

## 6. CVSS 3.1 — COMMON PATTERNS

```
IDOR read PII (auth required):     AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N = 6.5 Medium
Auth bypass → admin (no auth):     AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H = 9.8 Critical
SSRF → cloud metadata:             AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N = 9.1 Critical
Stored XSS (scope changed):        AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:L/A:N = 8.2 High
OAuth state CSRF (user interaction): AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N = 5.4 Medium
```

Don't overclaim — triagers trust you less for every overclaim.
Don't underclaim — you're leaving money on the table.

## 7. REPORT FORMAT (HackerOne Default)

```markdown
## Summary
[One sentence: what attacker can do, to whom, how]

## Vulnerability Details
**Endpoint:** [exact URL]
**Method:** [GET/POST/etc]
**Parameter:** [affected parameter]
**CWE:** [CWE-XXX]
**CVSS 3.1:** [score] ([vector string])

## Steps to Reproduce
1. [Setup - accounts needed]
2. [Exact HTTP request]
3. [What to observe]

## Proof of Concept
```bash
[Copy-pasteable curl command]
```

**Response:**
```json
[Actual response showing impact]
```

## Impact
[What attacker gets. Quantify: how many users affected, what data, $ value]

## Recommended Fix
[1-2 specific sentences]
```

Keep under 600 words. Triagers skim.

## 8. ESCALATION LANGUAGE (when payout is downgraded)

```
"This requires only a free account — no special privileges."
"The exposed data includes [PII type], subject to GDPR/CCPA."
"An attacker can automate this — all [N] records in minutes."
"This is exploitable externally without internal access."
```

## 9. SEPARATE BUGS = SEPARATE REPORTS

Independent bugs → separate reports → separate payouts.
Only combine if they form ONE attack chain.

## 10. VERIFY DATA ISN'T ALREADY PUBLIC

Before reporting info disclosure:
1. Check the same endpoint without authentication
2. If same data visible → NOT a bug
3. Compare authenticated vs unauthenticated responses
