#!/bin/bash
# setup_hunter.sh — One-command dependency installer for HunterAI on Kali WSL2
# Run: chmod +x setup_hunter.sh && ./setup_hunter.sh

set -e
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${GREEN}╔══════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║       HunterAI Setup — Kali WSL2             ║${NC}"
echo -e "${GREEN}╚══════════════════════════════════════════════╝${NC}"

# ── Python Dependencies ──────────────────────────────────────────────────────
echo -e "\n${YELLOW}[1/5] Installing Python dependencies...${NC}"
pip3 install --quiet --break-system-packages \
    requests \
    aiohttp \
    beautifulsoup4 \
    lxml \
    pyyaml \
    python-dotenv \
    colorama \
    urllib3 \
    2>/dev/null || pip3 install --quiet \
    requests \
    aiohttp \
    beautifulsoup4 \
    lxml \
    pyyaml \
    python-dotenv \
    colorama \
    urllib3

echo -e "${GREEN}  ✓ Python packages installed${NC}"

# ── Security Tools ────────────────────────────────────────────────────────────
echo -e "\n${YELLOW}[2/5] Installing/verifying security tools...${NC}"

check_install() {
    if command -v "$1" &>/dev/null; then
        echo -e "  ${GREEN}✓${NC} $1 found"
        return 0
    else
        echo -e "  ${RED}✗${NC} $1 missing — installing..."
        return 1
    fi
}

# Go tools (subfinder, httpx, nuclei, etc.)
install_go_tool() {
    local tool=$1
    local repo=$2
    if ! check_install "$tool"; then
        if command -v go &>/dev/null; then
            go install "$repo@latest" 2>/dev/null && echo -e "  ${GREEN}✓${NC} $tool installed via go" || echo -e "  ${YELLOW}!${NC} $tool install failed — install manually"
        else
            echo -e "  ${YELLOW}!${NC} Go not found — install $tool manually"
        fi
    fi
}

install_go_tool "subfinder" "github.com/projectdiscovery/subfinder/v2/cmd/subfinder"
install_go_tool "httpx" "github.com/projectdiscovery/httpx/cmd/httpx"
install_go_tool "nuclei" "github.com/projectdiscovery/nuclei/v3/cmd/nuclei"
install_go_tool "katana" "github.com/projectdiscovery/katana/cmd/katana"
install_go_tool "interactsh-client" "github.com/projectdiscovery/interactsh/cmd/interactsh-client"

# Kali native tools
for tool in sqlmap whatweb nikto nmap ffuf dirb; do
    if ! check_install "$tool"; then
        sudo apt-get install -y "$tool" 2>/dev/null || echo -e "  ${YELLOW}!${NC} $tool not in apt"
    fi
done

# ── Interactsh Setup ─────────────────────────────────────────────────────────
echo -e "\n${YELLOW}[3/5] Setting up out-of-band (OOB) callback...${NC}"
if command -v interactsh-client &>/dev/null; then
    echo -e "  ${GREEN}✓${NC} interactsh-client available"
    echo -e "  ${YELLOW}TIP:${NC} Run 'interactsh-client' in a separate terminal during hunts"
else
    echo -e "  ${YELLOW}!${NC} interactsh-client not found — blind SSRF/XXE testing limited"
fi

# ── Nuclei Templates Update ──────────────────────────────────────────────────
echo -e "\n${YELLOW}[4/5] Updating nuclei templates...${NC}"
if command -v nuclei &>/dev/null; then
    nuclei -update-templates 2>/dev/null && echo -e "  ${GREEN}✓${NC} Templates updated" || echo -e "  ${YELLOW}!${NC} Template update failed"
else
    echo -e "  ${YELLOW}!${NC} nuclei not installed"
fi

# ── Environment File ─────────────────────────────────────────────────────────
echo -e "\n${YELLOW}[5/5] Checking environment config...${NC}"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ENV_FILE="$SCRIPT_DIR/.env"

if [ ! -f "$ENV_FILE" ]; then
    cat > "$ENV_FILE" << 'ENVEOF'
# HunterAI Environment Config
# Fill in as needed

# Ollama
OLLAMA_HOST=http://localhost:11434

# GitHub token (for git_recon.py)
# GITHUB_TOKEN=ghp_xxxx

# Auth token for target (set per hunt)
# HUNT_AUTH_TOKEN=Bearer xxx

# Interactsh callback URL (set from interactsh-client output)
# INTERACTSH_URL=xxxxx.oast.fun
ENVEOF
    echo -e "  ${GREEN}✓${NC} Created .env template at $ENV_FILE"
else
    echo -e "  ${GREEN}✓${NC} .env already exists"
fi

# ── Verify ────────────────────────────────────────────────────────────────────
echo -e "\n${GREEN}╔══════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║            Setup Complete!                    ║${NC}"
echo -e "${GREEN}╚══════════════════════════════════════════════╝${NC}"
echo -e "\nRun smoke test: ${YELLOW}python3 tools/smoke_test.py${NC}"
echo -e "Start hunting:  ${YELLOW}python3 agent.py --target example.com${NC}"
