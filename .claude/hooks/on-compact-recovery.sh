#!/bin/bash
# Fires on SessionStart after a compact event.
# Reads the active hunt state and injects context summary so Claude knows where it left off.

set -euo pipefail

SESSIONS_DIR="hunt-memory/sessions"
if [ ! -d "$SESSIONS_DIR" ]; then
    exit 0
fi

LATEST=$(find "$SESSIONS_DIR" -name "*_state.json" -printf '%T@ %p\n' 2>/dev/null | sort -rn | head -1 | cut -d' ' -f2-)

if [ -z "$LATEST" ] || [ ! -f "$LATEST" ]; then
    exit 0
fi

SUMMARY=$(python3 -c "
import json
try:
    with open('$LATEST') as f:
        s = json.load(f)
    target = s.get('target', 'unknown')
    phase = s.get('current_phase', 'unknown')
    endpoint = s.get('current_endpoint', 'unknown')
    completed = s.get('completed_tools', [])
    findings = s.get('findings', [])
    observations = s.get('observations', [])[-10:]  # last 10 only
    dead_ends = s.get('dead_ends', [])[-5:]
    tested = s.get('tested_classes', [])

    print(f'HUNT STATE RECOVERY — Target: {target}')
    print(f'Phase: {phase} | Current endpoint: {endpoint}')
    print(f'Completed tools: {len(completed)} | Findings: {len(findings)} | Tested classes: {len(tested)}/24')
    if observations:
        print('Last observations:')
        for o in observations:
            print(f'  - [{o.get(\"ts\",\"\")}] {o.get(\"cmd\",\"\")} => {o.get(\"result\",\"\")[:100]}')
    if dead_ends:
        print('Recent dead ends:')
        for d in dead_ends:
            print(f'  - {d}')
    if findings:
        print(f'Findings so far: {[f.get(\"title\",\"untitled\") for f in findings]}')
except Exception as e:
    print(f'Error reading state: {e}')
" 2>/dev/null || echo "No active hunt state found.")

# Output as additionalContext for Claude
echo "{\"additionalContext\": \"$SUMMARY\"}"

exit 0
