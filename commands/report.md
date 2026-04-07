---
description: "Generate submission-ready bug bounty report. Auto-runs after /validate passes. Never generates a report without validation. Usage: /report (auto-runs inside /fullhunt)"
---

# /report — Auto-Generate Submission-Ready Report

**Pre-condition:** `/validate` must PASS before this runs. Never write a report for an unvalidated finding.

## Report Structure (HackerOne Default)

### Title Formula (NEVER deviate)
```
[Bug Class] in [Exact Endpoint] allows [actor] to [impact]
```

### Template

```markdown
## Summary
[One sentence: what attacker can do + to whom + how. NO "could potentially".]

## Vulnerability Details
**Endpoint:** `[exact URL with path]`
**Method:** `[HTTP method]`
**Parameter:** `[affected parameter/field]`
**CWE:** `[CWE-XXX (exact)]`
**CVSS 3.1:** `[score]` (`[vector string]`)

## Steps to Reproduce

1. **Setup:** Create two accounts — Account A (attacker) and Account B (victim).
2. **As attacker (Account A):**
   ```bash
   curl -s -H "Authorization: Bearer ATTACKER_TOKEN" \
     "https://api.target.com/endpoint/VICTIM_ID"
   ```
3. **Observe:** Response contains victim's private data:
   ```json
   {"name":"victim","email":"victim@email.com","ssn":"***"}
   ```

## Impact
[What attacker walks away with. Quantify: users affected, data type, $ value.
Use present tense: "An attacker can...", never "could potentially..."]

## Recommended Fix
[1-2 specific, actionable sentences. Reference RFC or OWASP when applicable.]
```

### Word Count: Under 600 words
Triagers skim. Long reports get skimmed harder.

## Proof Requirements Checklist (auto-verify)

Before generating the report, confirm you have:

```
[ ] Copy-pasteable curl/HTTP request that reproduces the bug
[ ] Actual response body showing impact (not just status code)
[ ] Two accounts used for IDOR (attacker seeing victim data)
[ ] CVSS 3.1 score calculated with vector string
[ ] Title follows the formula exactly
[ ] First sentence states exact impact (no "could")
[ ] Fix recommendation is specific (not generic "validate input")
[ ] Under 600 words
```

## Writing Rules

1. **Impact first** — sentence 1 = what attacker gets
2. **Never theoretical** — show actual data, not possibilities
3. **Quantify** — how many users, what data type, $ value
4. **Human tone** — write to a person, not a system
5. **Specific fix** — "validate `state` parameter matches session" not "add CSRF protection"

## CVSS Quick Reference

```
IDOR read PII (auth needed):       6.5 Medium  AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N
IDOR write (auth needed):          8.1 High     AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N
Auth bypass → admin:               9.8 Critical AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
SSRF → cloud metadata:             9.1 Critical AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N
Stored XSS (scope change):         8.2 High     AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:L/A:N
OAuth CSRF (user interaction):     5.4 Medium   AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N
Open redirect chain → ATO:         8.2 High     AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N
JWT alg=none accepted:             9.1 Critical AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N
```
