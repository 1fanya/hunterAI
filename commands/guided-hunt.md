---
description: "Human-AI collaborative bug hunt — you provide app intelligence, Claude tests your hypotheses at scale. For $5K–$50K bugs that autopilot misses. Usage: /guided-hunt target.com"
---

# /guided-hunt <target> — Human-AI Collaborative Hunt

You (the human) provide application intelligence. I (Claude) test your hypotheses at scale.
This mode finds the $5,000–$50,000 bugs that autopilot misses.

## Workflow

### Step 1: Human provides app-intel

Before running `/guided-hunt`, create or update:
`hunt-memory/<target>/app-intel.md`

Template (copy and fill in):

```markdown
# App Intelligence: <target>

## What the app does
(e-commerce, SaaS, social, fintech — one sentence)

## Most sensitive actions
(payment, password reset, data export, admin — list top 3)

## Most valuable data
(PII, financial, credentials, private content — list top 3)

## Trust boundaries
(user vs admin, free vs paid, tenant A vs tenant B)

## Auth mechanism
(session cookies, JWT, OAuth, API keys — describe what you saw in Burp/devtools)

## Interesting endpoints I noticed
(paste raw endpoints from Burp/devtools, note anything weird)
Example:
- GET /api/v2/orders/{id} — returns full order with PII, only checks session cookie
- POST /api/v2/billing/apply-coupon — no rate limit visible
- GET /connect/google?redirect_uri=... — state param present but short

## My hypotheses
(what do you think is vulnerable and why)
Example:
- IDOR on /api/v2/orders/{id} — probably no ownership check
- Race condition on /apply-coupon — single-use coupon may be double-claimable
- OAuth state on /connect/google — 8 chars, might be brute-forceable

## Auth tokens (TWO accounts required for IDOR)
Account A (attacker): Cookie: session=abc123...  OR  Authorization: Bearer eyJ...
Account B (victim):   Cookie: session=xyz789...  OR  Authorization: Bearer eyJ...
```

### Step 2: Claude reads app-intel and executes

When human types `/guided-hunt <target>`:

1. Read `hunt-memory/<target>/app-intel.md` — STOP if it doesn't exist or is empty.
   Tell the human: "Create app-intel.md first. I need your brain before I can use mine."

2. Read each hypothesis from the file.

3. For each hypothesis, in priority order:
   a) State the hypothesis out loud (one line)
   b) Design the test (what requests, what to compare)
   c) Execute using the auth-pair (Account A vs Account B)
   d) Analyze the response CAREFULLY — read the actual body, not just status code
   e) Verdict: CONFIRMED (proceed to validation) or BUSTED (log dead end with why)

4. After all human hypotheses are tested, run autonomous expansion:
   "Based on what I found and the app-intel, here are 5 additional hypotheses I want to test..."
   Test those too.

5. For every confirmed finding: 7-Question Gate → chain check → report.

### Key rules for guided mode

- NEVER skip reading app-intel.md. It's the human's thinking — it's more valuable than any tool.
- Test hypotheses in the ORDER the human listed them. They know their intuition.
- When a hypothesis is BUSTED, explain WHY in one sentence. The human learns from this.
- After testing all hypotheses, suggest NEW ones based on patterns you noticed.
- Use auth-pair for every IDOR/BOLA test. No exceptions.

## Auth pair setup

For IDOR testing, create `hunt-memory/<target>/auth-pair.json`:

```json
{
  "base_url": "https://target.com",
  "attacker": {"cookies": {"session": "ATTACKER_SESSION_HERE"}, "headers": {}},
  "victim":   {"cookies": {"session": "VICTIM_SESSION_HERE"},   "headers": {}},
  "rate_limit": 0.5
}
```

Or generate the template:
```bash
python3 tools/auth_pair.py --init target
```

Then in testing:
```python
from auth_pair import AuthPair
pair = AuthPair.load("target")
result = pair.test_idor("/api/v2/orders/VICTIM_ORDER_ID")
if result["idor_likely"]:
    # proceed to 7-Question Gate
```

## After /guided-hunt

1. Review confirmed findings with `/validate`
2. Check for chains with `/chain`
3. Submit via HackerOne API or manually
4. Run `/remember` to save working techniques to hunt-vault
