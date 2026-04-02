---
description: "Resume a previous hunt that was interrupted (limits, crash, close). Loads saved state and continues from exactly where you left off. Usage: /resume target.com"
---

# /resume — Resume Interrupted Hunt

Resumes from the exact step where you left off. Uses `hunt_state.py` to load saved state from disk.

## Usage

```
/resume target.com
```

## How It Works

### Step 1: Load State (Haiku/min effort)

```python
import sys, os
sys.path.insert(0, os.path.join(os.getcwd(), "tools"))
from hunt_state import HuntState

state = HuntState("TARGET_DOMAIN")
phase = state.get_phase()
```

### Step 2: Check If There's Anything to Resume

If `phase == "init"` → No previous hunt found. Tell user to run `/fullhunt target.com` instead.

If `phase == "done"` → Hunt already completed. Show final stats and point to reports.

Otherwise → Print resumption prompt and continue.

### Step 3: Print Status

```python
print(state.get_status_summary())
print(state.get_resumption_prompt())
```

This outputs:
```
Phase: hunting | Step: 14 | Tools: 8 done, 1 failed | Findings: 3 | Chains: 1

## RESUMING HUNT: target.com
### Completed tools (8):
hunt_intel, learn_hacktivity, recon, waf_detect, nuclei_gen, api_discovery, ...

### Findings so far:
- [HIGH] IDOR: https://target.com/api/users/123
- [CRITICAL] SSRF: https://target.com/proxy?url=
- [MEDIUM] Open Redirect: https://target.com/redirect?to=

### Next: Continue from phase 'hunting', skip completed tools.
```

### Step 4: Continue the Hunt

**CRITICAL RULES FOR RESUME:**

1. **DO NOT re-run completed tools** — check `state.is_tool_completed("tool_name")` first
2. **DO NOT re-read recon data** if already in `state.state["recon"]`
3. **DO NOT re-analyze scope** if already in `state.state["scope"]`
4. **Start from the current phase** — don't go back to Phase 0
5. **Use the same model/effort routing** as fullhunt.md

### Step 5: Continue Running Fullhunt Pipeline

Pick up from the current phase and continue through the fullhunt pipeline.
Skip all tools that `state.is_tool_completed()` returns True for.
Save state after every tool with `state.complete_tool()`.

## State File Location

```
hunt-memory/sessions/<target>_state.json
```

## What's Saved

- Phase, step counter
- Scope (in-scope, out-of-scope domains)
- Recon results (subdomains, live hosts, tech stack, URLs)
- All completed/skipped/failed tools
- All findings with timestamps
- All chains discovered
- Endpoints tested vs remaining
- Model usage stats

## Edge Cases

| Situation | Action |
|-----------|--------|
| State file corrupted | Start fresh, warn user |
| State file from >7 days ago | Warn about stale recon, offer fresh start |
| Tool was mid-execution when interrupted | Re-run only that tool |
| New endpoints discovered since last run | Add to remaining queue |
