---
description: "Check a finding against HackerOne Hacktivity for duplicates before submitting. Usage: /compare IDOR on /api/users/{id} [--program shopify]"
---

# /compare — Dedup Check Against Hacktivity

Check if your finding has already been reported before wasting time writing it up.

## Usage

```
/compare IDOR on /api/v2/users/{id} allows reading other user's data
/compare IDOR on /api/v2/users/{id} --program shopify
/compare --finding-file findings/target.com/verified_exploits.json --program uber
```

## What It Does

1. Checks against the **always-rejected list** (35+ patterns that always get closed)
2. Queries **HackerOne Hacktivity** for similar disclosed reports on the program
3. Calculates **similarity score** based on vuln class + endpoint pattern
4. Outputs verdict: `SUBMIT` / `LIKELY_DUPLICATE` / `POSSIBLE_DUPLICATE` / `REJECTED`

## Verdicts

| Verdict | Action |
|---------|--------|
| `SUBMIT` | No duplicates found — go ahead and submit |
| `POSSIBLE_DUPLICATE` | Similar report exists — make sure your PoC shows a DIFFERENT endpoint |
| `LIKELY_DUPLICATE` | Very similar report already disclosed — consider skipping |
| `REJECTED` | Matches always-rejected pattern — don't submit unless you can chain it |

## Example Output

```
  Verdict: SUBMIT
  LOW duplicate risk. Some related reports exist but your finding
  appears to be distinct. Submit with confidence.

  Similar disclosed reports:
    1. [high] IDOR in user profile API (35% match)
       Disclosed: 2024-11-15
```

## Under the Hood

```bash
python3 tools/report_comparer.py --program shopify \
  --finding "IDOR on /api/users/{id} allows reading PII"
```
