#!/bin/bash
# Auto-log tool results to hunt state after every Bash tool call.
# Receives JSON on stdin with tool_input and tool_response.
# Appends a one-line summary to the active hunt session's observations log.

set -euo pipefail

INPUT=$(cat)

# Extract tool command and truncated response (first 200 chars)
TOOL_CMD=$(echo "$INPUT" | python3 -c "
import json, sys
try:
    d = json.load(sys.stdin)
    cmd = d.get('tool_input', {}).get('command', 'unknown')
    # Truncate to first line, max 150 chars
    print(cmd.split('\n')[0][:150])
except:
    print('unknown')
" 2>/dev/null || echo "unknown")

TOOL_RESP=$(echo "$INPUT" | python3 -c "
import json, sys
try:
    d = json.load(sys.stdin)
    resp = str(d.get('tool_response', ''))[:200]
    # Single line, escape newlines
    print(resp.replace('\n', ' | ')[:200])
except:
    print('')
" 2>/dev/null || echo "")

# Find active hunt session and append observation
TIMESTAMP=$(date -u +%Y-%m-%dT%H:%M:%SZ)
SESSIONS_DIR="hunt-memory/sessions"

if [ -d "$SESSIONS_DIR" ]; then
    # Find most recently modified state file
    LATEST=$(find "$SESSIONS_DIR" -name "*_state.json" -printf '%T@ %p\n' 2>/dev/null | sort -rn | head -1 | cut -d' ' -f2-)
    if [ -n "$LATEST" ] && [ -f "$LATEST" ]; then
        python3 -c "
import json, sys
try:
    with open('$LATEST', 'r') as f:
        state = json.load(f)
    if 'observations' not in state:
        state['observations'] = []
    # Keep last 50 observations to prevent bloat
    obs = {'ts': '$TIMESTAMP', 'cmd': '''$TOOL_CMD''', 'result': '''$TOOL_RESP'''}
    state['observations'].append(obs)
    state['observations'] = state['observations'][-50:]
    with open('$LATEST', 'w') as f:
        json.dump(state, f, indent=2)
except Exception as e:
    pass  # Silent fail — never block the hunt
" 2>/dev/null
    fi
fi

exit 0
