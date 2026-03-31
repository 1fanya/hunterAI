---
description: "Resume a previous hunt — loads saved state, shows progress, and continues from where you left off. Session-persistent across Claude Code restarts. Usage: /resume target.com"
---

# /resume — Resume Previous Hunt

Pick up exactly where you left off. Session state is saved automatically.

## Usage

```
/resume target.com
```

## What This Does

1. Loads saved hunt state from `hunt-memory/sessions/<target>_state.json`
2. Shows complete progress summary:
   - Current phase (recon/ranking/hunting/validating/reporting)
   - Endpoints tested vs remaining
   - Findings (validated, killed, partial signals)
   - Chain candidates to investigate
   - Model usage (Haiku/Sonnet/Opus calls)
3. Shows recent activity log (last 10 actions)
4. Recommends next action
5. Continues the hunt from the exact point it stopped

## How It Works

Every `/fullhunt`, `/hunt`, and `/autopilot` session automatically saves state:
- Phase progress
- Scope configuration
- Recon results summary
- Attack surface ranking (P1/P2/Kill)
- Every tested endpoint + result
- Every untested endpoint remaining
- All findings (with PoC data)
- Validation results
- Chain candidates
- Generated reports
- Model usage tracking

When you close Claude Code and reopen:
```
/resume target.com
```

Claude reads the state file and continues from the exact step.

## Output Example

```
╔══════════════════════════════════════════════════╗
║  HUNT STATE: target.com                          ║
╚══════════════════════════════════════════════════╝

  Phase:     hunting
  Started:   2026-03-30T12:00:00
  Updated:   2026-03-30T14:30:00
  Cost mode: balanced

  Recon: ✓ 142 subs, 38 live, 1250 URLs, 3 nuclei findings
  Ranking: ✓ 12 P1, 24 P2, 6 killed
  Endpoints: 8 tested, 28 remaining
  Findings: 2 total, 1 validated, 0 killed
  Partial signals: 3
  Chain candidates: 1 untested

  Model calls: Haiku=15, Sonnet=42, Opus=1

  Recent activity:
    [14:28:32] Tested: /api/v2/orders/{id} [idor] → finding
    [14:29:15] Finding: FIND-002 — idor on /api/v2/orders/{id}
    [14:30:00] Phase: hunting → hunting (continuing)

  ► Next: Continue hunting — next: /api/v2/users/{id}/export
```

## Under the Hood

```bash
python3 tools/hunt_state.py target.com --show
```

## If No Previous Hunt

```
No previous state found for target.com
Start a new hunt with: /fullhunt target.com
```
