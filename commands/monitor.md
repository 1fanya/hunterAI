---
description: "Set up background monitoring on a target domain. Runs periodic recon scans and diffs against previous results to detect new attack surface. Usage: /monitor target.com"
---

# /monitor — Background Target Monitoring

Be the first to find new attack surface.

## Usage

```
/monitor target.com         # Run monitoring scan now
/monitor target.com --diff  # Show what changed since last scan
/monitor target.com --cron  # Generate crontab entry for automation
```

## What It Does

1. Runs subdomain enumeration (subfinder + assetfinder)
2. Crawls URLs (katana + waybackurls + gau)
3. Checks Certificate Transparency logs (crt.sh)
4. **Diffs against previous scan results**
5. Alerts on new subdomains, URLs, and domains
6. Saves history for trend analysis

## Automation

Generate a crontab entry that runs every 6 hours:
```
/monitor target.com --cron
```

This adds something like:
```
0 */6 * * * cd /path/to/claude-bug-bounty && python3 tools/monitor_agent.py --target target.com --run >> hunt-memory/monitor/cron.log 2>&1
```

## When New Attack Surface Is Found

Run `/fullhunt` on the new subdomains/endpoints — they're the most likely to have bugs because:
- New features = new code = new vulnerabilities
- Developers focused on feature delivery, not security
- WAF rules may not cover new endpoints yet
