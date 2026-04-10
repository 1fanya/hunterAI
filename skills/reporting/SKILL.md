---
name: reporting
description: Report quality rules, 7-Question Validation Gate, title formula, CVSS guide, never-submit list
---

## Report Quality Rules (auto-enforced)

1. **NEVER say "could potentially"** — concrete statements only
2. **TITLE FORMULA**: `[Bug Class] in [Endpoint] allows [actor] to [impact]`
3. **COPY-PASTEABLE PoC** — curl command that reproduces the bug
4. **ACTUAL RESPONSE DATA** — not just "200 OK"
5. **UNDER 600 WORDS** — triagers skim
6. **CVSS 3.1 WITH VECTOR** — don't overclaim, don't underclaim
7. **SEPARATE BUGS = SEPARATE REPORTS** — independent bugs → separate payouts

## 7-Question Validation Gate

Run every finding through ALL 7 questions. One KILL → discard finding.

1. **Is the endpoint reachable?** (live, returns non-404/redirect) → KILL if no
2. **Is it in scope?** (domain/asset listed in program scope) → KILL if no
3. **Can an attacker trigger it without special access?** → KILL if no
4. **Does it affect real user data or program assets?** → KILL if no
5. **Is it reproducible?** (consistent, not intermittent) → KILL if no
6. **Is it a known/disclosed duplicate?** (Hacktivity check) → KILL if yes
7. **Is the impact concrete, not theoretical?** → KILL if theoretical

## Never-Submit List (auto-KILL — always rejected)

- Missing security headers (CSP, X-Frame-Options, HSTS) — standalone
- GraphQL introspection enabled — standalone (no data extraction)
- Self-XSS (requires own account, no CSRF chain)
- Open redirect — standalone (no OAuth/SSRF chain)
- Clickjacking — standalone (no sensitive action)
- Rate limiting missing — standalone (no brute-force impact)
- SPF/DMARC/DKIM issues
- Software version disclosure — standalone
- SSL/TLS configuration issues — standalone
- Cookie flags (HttpOnly/Secure) missing — standalone

## Conditionally Valid (need a chain)

| Bug alone | Needs | Becomes |
|-----------|-------|---------|
| Open redirect | OAuth flow | Token theft → ATO |
| Self-XSS | CSRF | Stored XSS via CSRF |
| SSRF (internal) | Cloud metadata | Credential theft → RCE |
| Subdomain takeover | Auth cookies | Session hijack |

## CVSS 3.1 Quick Reference

- **Critical (9.0-10.0)**: RCE, auth bypass on all accounts, mass data exposure
- **High (7.0-8.9)**: IDOR with PII, SQLi with data, stored XSS on sensitive page
- **Medium (4.0-6.9)**: Reflected XSS, IDOR with non-sensitive data, CORS misconfiguration
- **Low (0.1-3.9)**: Information disclosure, self-XSS with chain, minor logic flaws

Always include vector string: `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N`
