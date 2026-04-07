---
description: "Auto-validate a finding before report. Runs 7-Question Gate + 4-gate checklist. Kills weak findings before wasting tokens on reports. Usage: /validate (runs automatically inside /fullhunt)"
---

# /validate — Auto-Validation Gate

Runs AUTOMATICALLY inside `/fullhunt` after every finding, before report generation.
Can also run standalone: type `/validate` and describe the finding.

## What This Does (Autonomously)

1. Runs 7-Question Gate (ONE fail = KILL finding)
2. Checks against never-submit list (auto-reject)
3. Runs 4 pre-submission gates
4. Checks proof requirements for the specific vuln class
5. Output: **PASS** (generate report) or **KILL** (move on silently)

## 7-Question Gate (ALL must pass)

### Q1: Can I demonstrate this step-by-step RIGHT NOW?
Write out internally:
```
1. Setup:   [account type needed]
2. Request: [exact HTTP request]
3. Result:  [exact response data]
4. Impact:  [real consequence]
```
If request returns timeout/5xx/error → KILL.
If result is just a status code without data → KILL.

### Q2: Is the impact accepted by this program?
Cross-check program scope. Auto-KILL if bug class is excluded.

### Q3: Is the vulnerable asset in scope?
Verify exact domain is listed. Third-party services = out of scope.

### Q4: Does it need privileged access an attacker can't get?
"Admin can do X" → KILL.

### Q5: Is this known/documented behavior?
Check Hacktivity, changelogs. If documented → KILL.

### Q6: Can I prove impact beyond "technically possible"?
Must have actual data/action proof per vuln class:
- **IDOR**: victim's private data in attacker's response
- **XSS**: cookie exfiltration or DOM write
- **SSRF**: internal service response body
- **OAuth**: silent redirect with code (no consent screen)
- **JWT**: forged token accepted by server
- **SQLi**: database content extracted
- **XXE**: file read or OOB data exfil
- **Open redirect**: chained to OAuth/token theft

### Q7: Is this on the never-submit list?
Auto-reject from `rules/hunting.md` list unless chain proven.

## 4 Gates (all auto-checked)

**Gate 0:** Real HTTP request made? In scope? Reproducible? Evidence saved?
**Gate 1:** Attacker gains what? Real victim? No unlikely preconditions?
**Gate 2:** Not duplicate in Hacktivity? Not documented behavior?
**Gate 3:** Title formula? HTTP request in steps? Evidence shows data? CVSS?

## Decision Output

```
PASS → proceed to report generation
KILL → discard finding, log reason, move to next endpoint
DOWNGRADE → adjust severity, proceed to report
```

## Integration in /fullhunt Pipeline

```python
# After finding a potential vulnerability:
for finding in potential_findings:
    validation = auto_validate(finding)
    if validation == "KILL":
        state.log_killed(finding, reason)
        continue  # Move on — don't waste tokens
    if validation == "DOWNGRADE":
        finding["severity"] = downgraded_severity
    # Only reaches here if PASS or DOWNGRADE
    state.add_finding(finding)
    generate_report(finding)
```
