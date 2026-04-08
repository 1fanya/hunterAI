#!/bin/bash
# ─── HunterAI MCP Setup ──────────────────────────────────────────────────────
# Registers both MCP servers (HackerOne + Burp) with Claude Code.
#
# Usage:
#   chmod +x mcp/setup_mcp.sh && ./mcp/setup_mcp.sh
#
# Prerequisites:
#   - Claude Code CLI installed
#   - For Burp MCP: Burp Suite running with --rest-api
#   - For H1 auth: H1_API_USERNAME + H1_API_TOKEN in .env
# ──────────────────────────────────────────────────────────────────────────────

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

echo "╔══════════════════════════════════════════════════╗"
echo "║       HunterAI MCP Server Setup                  ║"
echo "╚══════════════════════════════════════════════════╝"
echo ""

# Load .env if exists
if [ -f "$PROJECT_DIR/.env" ]; then
    echo "[*] Loading .env ..."
    export $(grep -v '^#' "$PROJECT_DIR/.env" | xargs)
fi

# ─── Register HackerOne MCP ──────────────────────────────────────────────────
echo ""
echo "[1/2] Registering HackerOne MCP server..."

H1_ENV_ARGS=""
if [ -n "$H1_API_USERNAME" ] && [ -n "$H1_API_TOKEN" ]; then
    H1_ENV_ARGS="--env H1_API_USERNAME=$H1_API_USERNAME --env H1_API_TOKEN=$H1_API_TOKEN"
    echo "  ✓ Auth configured (username: $H1_API_USERNAME)"
else
    echo "  ⚠ No H1 auth — public tools only (set H1_API_USERNAME + H1_API_TOKEN)"
fi

claude mcp add hackerone \
    --scope project \
    -- python3 "$PROJECT_DIR/mcp/hackerone-mcp/server.py" \
    $H1_ENV_ARGS 2>/dev/null && echo "  ✓ HackerOne MCP registered" || echo "  ⚠ Failed (try manually)"

# ─── Register Burp Suite MCP ─────────────────────────────────────────────────
echo ""
echo "[2/2] Registering Burp Suite MCP server..."

BURP_URL="${BURP_API_URL:-http://127.0.0.1:1337}"
BURP_KEY_ARG=""
if [ -n "$BURP_API_KEY" ]; then
    BURP_KEY_ARG="--env BURP_API_KEY=$BURP_API_KEY"
fi

claude mcp add burp \
    --scope project \
    --env BURP_API_URL="$BURP_URL" \
    $BURP_KEY_ARG \
    -- python3 "$PROJECT_DIR/mcp/burp-mcp-client/server.py" \
    2>/dev/null && echo "  ✓ Burp MCP registered" || echo "  ⚠ Failed (try manually)"

# ─── Verify ──────────────────────────────────────────────────────────────────
echo ""
echo "─── Verification ───"
echo ""
claude mcp list 2>/dev/null || echo "(Run 'claude mcp list' to verify)"

echo ""
echo "╔══════════════════════════════════════════════════╗"
echo "║  Setup complete!                                 ║"
echo "║                                                  ║"
echo "║  Quick test:                                     ║"
echo "║    python3 mcp/hackerone-mcp/server.py search ssrf║"
echo "║    python3 mcp/burp-mcp-client/server.py history ║"
echo "║                                                  ║"
echo "║  In Claude Code:                                 ║"
echo "║    claude mcp list                               ║"
echo "╚══════════════════════════════════════════════════╝"
