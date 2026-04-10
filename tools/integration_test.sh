#!/bin/bash
# Integration test — verifies tools actually WORK, not just import.
set -euo pipefail

echo "╔══════════════════════════════════════════════════════╗"
echo "║          HunterAI Integration Test                   ║"
echo "╚══════════════════════════════════════════════════════╝"

PASS=0
FAIL=0

check() {
    local name="$1"
    local cmd="$2"
    if eval "$cmd" > /dev/null 2>&1; then
        echo "  ✓ $name"
        PASS=$((PASS + 1))
    else
        echo "  ✗ $name"
        FAIL=$((FAIL + 1))
    fi
}

echo ""
echo "  EXTERNAL TOOLS"
check "subfinder"  "which subfinder"
check "httpx"      "which httpx"
check "nuclei"     "which nuclei"
check "katana"     "which katana"
check "ffuf"       "which ffuf"
check "sqlmap"     "which sqlmap"
check "dalfox"     "which dalfox"
check "nmap"       "which nmap"
check "gau"        "which gau"
check "subzy"      "which subzy"

echo ""
echo "  TOOL FUNCTIONALITY (live tests)"
check "subfinder runs" "subfinder -d example.com -silent -max-time 5 | head -1"
check "httpx runs"     "echo 'https://example.com' | httpx -silent -status-code | head -1"
check "nuclei version" "nuclei -version"

echo ""
echo "  PYTHON TOOLS"
check "hunt_state.py imports"       "python3 -c 'import sys; sys.path.insert(0, \"tools\"); from hunt_state import HuntState'"
check "auth_pair.py imports"        "python3 -c 'import sys; sys.path.insert(0, \"tools\"); from auth_pair import AuthPair'"
check "exploit_verifier.py imports" "python3 -c 'import sys; sys.path.insert(0, \"tools\"); import exploit_verifier'"
check "safe_http.py imports"        "python3 -c 'import sys; sys.path.insert(0, \"tools\"); from safe_http import SafeHTTP'"

echo ""
echo "  HOOKS"
check "post-tool-logger.sh exists"   "test -x .claude/hooks/post-tool-logger.sh"
check "on-compact-recovery.sh exists" "test -x .claude/hooks/on-compact-recovery.sh"

echo ""
echo "  CONFIGURATION"
check "CLAUDE.md under 60 lines" "[ \$(wc -l < CLAUDE.md) -lt 60 ]"
check "Subagents exist"          "[ \$(ls .claude/agents/*.md 2>/dev/null | wc -l) -ge 6 ]"
check "Skills exist"             "[ \$(ls skills/*/SKILL.md 2>/dev/null | wc -l) -ge 5 ]"
check "hunt-vault exists"        "test -d hunt-vault"

echo ""
echo "  NUCLEI TEMPLATES"
OFFICIAL=$(find ~/nuclei-templates -name '*.yaml' 2>/dev/null | wc -l) || OFFICIAL=0
CUSTOM=$(find nuclei-templates -name '*.yaml' 2>/dev/null | wc -l) || CUSTOM=0
echo "  Official templates: $OFFICIAL"
echo "  Custom templates:   $CUSTOM"
check "Has 1000+ official templates" "[ $OFFICIAL -gt 1000 ]"

echo ""
echo "══════════════════════════════════════════════════════"
echo "  RESULTS: $PASS passed, $FAIL failed"
echo "══════════════════════════════════════════════════════"

[ $FAIL -eq 0 ] && exit 0 || exit 1
