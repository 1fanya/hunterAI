---
description: Always-active hunting rules. These are enforced automatically during /fullhunt — never ask the user.
---

# Hunting Rules (Always Active)

These rules are NON-NEGOTIABLE. During autonomous hunting, enforce every one silently.

## 1. NO THEORETICAL BUGS

> "Can an attacker do this RIGHT NOW, against a real user, causing real harm?"
> If NO — KILL IT. Do not explore further. Do not write it up. Move on.

```
NOT a bug: "Could theoretically allow..."
NOT a bug: "Wrong but no practical impact"
NOT a bug: "3+ unlikely preconditions required simultaneously"
NOT a bug: Dead/unreachable code
NOT a bug: SSRF with DNS callback only (no internal data)
NOT a bug: Missing headers without demonstrated exploit
```

## 2. VERIFY BEFORE YOU REPORT — EVERY TIME

Before generating ANY finding, you MUST:
1. **Confirm the endpoint is reachable** (HTTP 200/302, not timeout/5xx)
2. **Prove impact with actual data** (not just status codes)
3. **Test with 2 accounts** for IDOR (attacker sees victim's data)
4. **Confirm consent/auth bypass** for OAuth (auto-redirect, no consent screen)
5. **Show actual response content** for info disclosure (not just 200 OK)

If you can't do step 2 → it's NOT a finding. KILL IT.

## 3. PROOF REQUIREMENTS BY VULNERABILITY CLASS

| Vuln Class | Required Proof (without this = KILL IT) |
|---|---|
| IDOR | Victim's actual private data in attacker's response |
| XSS | Cookie exfil or DOM manipulation (not just alert()) |
| SSRF | Internal service response body (not just DNS callback) |
| SQLi | Actual database content (not just error message) |
| Auth bypass | Access to protected resource without valid creds |
| OAuth | Silent redirect with code/token (no consent screen) |
| JWT | Forged token accepted by server (not just decoded) |
| XXE | File contents or OOB data (not just parser error) |
| SSTI | RCE output or file read (not just math reflection) |
| Open redirect | Only valid if chained (OAuth token theft, phishing) |
| Race condition | Actual duplicate action completed (not just fast response) |
| Cache poison | Poisoned response served to other users |

## 4. NEVER-SUBMIT LIST (Always N/A — auto-filter)

These are ALWAYS rejected standalone. Never report them alone:

```
Missing security headers (CSP, HSTS, X-Frame-Options)
GraphQL introspection enabled (alone)
Self-XSS (requires victim to paste in own console)
Open redirect alone (no chain)
SSRF with DNS-only callback (no internal data)
Logout CSRF
Missing cookie flags alone (HttpOnly, Secure, SameSite)
Rate limit on non-critical forms (login, search)
Banner/version disclosure without working exploit
Clickjacking without PoC on sensitive action
CORS misconfiguration without credentialed data exfil
Content-Type sniffing without demonstrated exploit
```

If you find one of these → check if it chains to something real.
If no chain → KILL IT. Do not waste tokens reporting it.

## 5. CHAIN BEFORE KILL — Conditionally Valid

| You Found | Chain Available? |
|---|---|
| Open redirect | + OAuth code theft → ATO? |
| SSRF DNS-only | + internal service data? |
| Clickjacking | + sensitive action + PoC? |
| CORS wildcard | + credentialed data exfil? |
| Self-XSS | + CSRF to force inject? |
| Missing header | + actual exploit using that gap? |

If chain confirmed → report both together. If no chain → KILL IT.

## 6. REACHABILITY CHECK (MANDATORY BEFORE EVERY FINDING)

Before recording ANY finding, run this check:

```python
# MUST pass before any finding is recorded
import requests
resp = requests.get(target_url, timeout=10, verify=False)
assert resp.status_code not in (0, 502, 503, 504), "Endpoint unreachable — KILL finding"
assert resp.status_code != 403 or "WAF" not in resp.text, "WAF blocking — verify bypass first"
```

## 7. IMPACT-FIRST HUNTING

Hunt features with highest business impact first:
1. **Payment/billing** — price manipulation, race on checkout
2. **Auth/session** — account takeover, privilege escalation
3. **Admin features** — auth bypass to admin
4. **PII endpoints** — IDOR on user data
5. **File handling** — upload, download, path traversal
6. **API** — BOLA/BFLA, mass assignment
7. **Everything else** — XSS, SSRF, etc.

## 8. 5-MINUTE RULE

Nothing interesting after 5 minutes on an endpoint → move on.
Fresh context finds more bugs than brute force.

## 9. THE SIBLING RULE

If `/api/user/123/orders` has auth → check:
- `/api/user/123/export`
- `/api/user/123/delete`
- `/api/user/123/share`

30% of paid IDOR bugs come from siblings.

## 10. A→B SIGNAL METHOD

When you confirm bug A → don't report yet → hunt B and C first.
A confirmed bug = the developer made a class of mistake.
They made it elsewhere too. Finding B costs 10x less than finding A.

## 11. DEPTH OVER BREADTH

One target deeply understood > ten targets shallowly tested.
Read 5+ disclosed reports for the target before hunting.

## 12. FOLLOW THE MONEY

Billing/credits/refunds/wallet = most developer shortcuts.
Always test: price manipulation, race on payment, quota bypass.

## 13. SEPARATE BUGS = SEPARATE REPORTS

If A and B are independent bugs (different endpoints, different impact):
Report them SEPARATELY = separate payouts.
Only combine if they're part of ONE attack chain.

## 14. DEDUP BEFORE REPORT

Before generating report for any finding:
1. Search HackerOne Hacktivity for endpoint + bug class
2. Check if vulnerability is documented behavior
3. If likely duplicate → KILL IT

## 15. CREDENTIAL LEAKS NEED EXPLOITATION PROOF

Finding an API key = Informational.
Proving what the key accesses (S3 read, database, admin) = Medium/High.
Always call the API as the leaked key. Enumerate permissions.
