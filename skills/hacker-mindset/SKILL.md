---
name: hacker-mindset
description: How to think like an elite bug bounty hunter. Read this before Phase 3.5 Application Intelligence and before every hunting session. This is about reasoning, not tools.
---

# Hacker Mindset

## The difference between a scanner and a hacker

A scanner runs tools against endpoints and reports what the tool found.
A hacker understands the application, forms hypotheses about where bugs live, and PROVES them.

Scanners find: known CVEs, reflected XSS, open redirects, misconfigured headers.
These pay $50-$500 and are usually duplicates.

Hackers find: IDOR chains, OAuth account takeovers, business logic bypasses, race conditions.
These pay $2,000-$50,000 and are rarely duplicated.

## How to think about every endpoint

When you see an endpoint like `POST /api/v2/billing/invoice/{id}/download`:

**Scanner thinking:** "Run sqlmap on the id parameter"

**Hacker thinking:** "This returns a PDF invoice. Does it check that {id} belongs to the authenticated user? What if I use another user's invoice ID? Does the PDF contain PII? Can I iterate through IDs to download all invoices? Is there a difference between the API response for 'exists but not yours' vs 'does not exist'?"

When you see an OAuth integration:

**Scanner thinking:** "Check if state parameter is present"

**Hacker thinking:** "The redirect_uri is validated, but does it accept subdirectories? /callback vs /callback/../other-page? Does it accept a different protocol? Does the state parameter get validated on the server or just checked for presence? What happens if I initiate the flow in browser A and complete it in browser B with a different session?"

## Rules for hypothesis-driven hunting

1. NEVER run a tool without first stating what you expect to find and why.
2. Spend more time reading API responses than running tools.
3. The HTTP response body tells you more than any scanner. Read it.
4. Look for INCONSISTENCIES: if one endpoint checks auth and a similar one doesn't, that's a bug.
5. Look for TRANSITIONS: what happens between states? Paid → cancelled → refunded. Can you skip steps?
6. Look for IMPLICIT TRUST: does the server trust the client for anything it shouldn't? Price, role, tenant ID, file type?
7. Two accounts are mandatory. If you can't test with two accounts, you can't find IDOR/BOLA.
8. After finding ANY bug, ask: "Can I chain this with something else to increase severity?"
9. A low-severity bug that chains into account takeover is worth 10x a standalone medium.
10. When stuck, switch perspective: "If I were the developer, what would I forget to check?"

## Common high-value patterns by application type

### SaaS / Multi-tenant
- Tenant isolation failures (IDOR across tenants)
- Admin panel accessible to regular users (direct URL, role manipulation)
- API versioning (v1 may lack auth checks that v2 has)
- Webhook/integration endpoints often skip auth
- Export/download features often have IDOR

### E-commerce
- Price manipulation (modify request body, negative quantities)
- Coupon/promo abuse (race condition on single-use coupons)
- Order ID IDOR (view/modify other users' orders)
- Payment flow bypass (skip to confirmation without payment)
- Address/PII leakage through order tracking

### Social / Community
- Private content access (posts, messages, media)
- User enumeration via error differences
- Account takeover via password reset flow
- Content injection (stored XSS in profiles, comments)
- Rate limit bypass on sensitive actions (login, 2FA)

### Fintech / Payments
- Race conditions on transfers/withdrawals (double-spend)
- Balance manipulation
- Transaction IDOR
- KYC bypass
- Negative amount transfers

## The question to ask before every test

> "If this bug is real, what is the worst-case impact for a real user?"

If the answer is "low" — test it quickly and move on.
If the answer is "account takeover" or "financial loss" — spend serious time here.

Allocate your energy proportional to impact, not proportional to what's easy to test.
