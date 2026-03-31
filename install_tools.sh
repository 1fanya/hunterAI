#!/bin/bash
# =============================================================================
# Bug Bounty Tool Installer — Kali Linux Edition
#
# Installs all required tools for autonomous bug bounty hunting.
# Optimized for Kali Linux which already has many security tools pre-installed.
#
# Usage: chmod +x install_tools.sh && ./install_tools.sh
# =============================================================================

set -euo pipefail

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

log_ok()   { echo -e "${GREEN}[+]${NC} $1"; }
log_err()  { echo -e "${RED}[-]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[!]${NC} $1"; }
log_info() { echo -e "${CYAN}[*]${NC} $1"; }

echo ""
echo -e "${BOLD}╔══════════════════════════════════════════════╗${NC}"
echo -e "${BOLD}║   Bug Bounty Tool Installer — Kali Linux     ║${NC}"
echo -e "${BOLD}╚══════════════════════════════════════════════╝${NC}"
echo ""

# ─── Check for root (some installs need it) ───
if [ "$EUID" -ne 0 ]; then
    log_warn "Not running as root. Some installs may need sudo."
fi

# ─── System dependencies ───
echo ""
log_info "Installing system dependencies..."
sudo apt-get update -qq 2>/dev/null
sudo apt-get install -y -qq golang python3 python3-pip nodejs npm jq curl wget git \
    nmap sqlmap chromium feroxbuster dnsutils whois 2>/dev/null || true
log_ok "System dependencies installed (including feroxbuster)"

# ─── Python dependencies ───
echo ""
log_info "Installing Python dependencies..."
pip3 install --quiet --break-system-packages \
    requests aiohttp beautifulsoup4 lxml colorama semgrep 2>/dev/null || \
pip3 install --quiet \
    requests aiohttp beautifulsoup4 lxml colorama semgrep 2>/dev/null || true
log_ok "Python dependencies installed"

# ─── Go environment ───
export GOPATH="${GOPATH:-$HOME/go}"
export PATH="$PATH:$GOPATH/bin:/usr/local/go/bin"

# Check Go is installed
if ! command -v go &>/dev/null; then
    log_err "Go not found. Installing..."
    sudo apt-get install -y golang 2>/dev/null || {
        log_err "Could not install Go. Please install manually."
        exit 1
    }
fi

GO_VERSION=$(go version 2>/dev/null | grep -oP '\d+\.\d+' | head -1)
log_ok "Go version: $GO_VERSION"

# ─── ProjectDiscovery Tools (Go-based — the core recon arsenal) ───
echo ""
log_info "Installing ProjectDiscovery tools..."

GO_TOOLS=(
    "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
    "github.com/projectdiscovery/httpx/cmd/httpx@latest"
    "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
    "github.com/projectdiscovery/katana/cmd/katana@latest"
    "github.com/projectdiscovery/dnsx/cmd/dnsx@latest"
    "github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest"
    "github.com/projectdiscovery/naabu/v2/cmd/naabu@latest"
)

GO_TOOL_NAMES=(
    "subfinder"
    "httpx"
    "nuclei"
    "katana"
    "dnsx"
    "interactsh-client"
    "naabu"
)

for i in "${!GO_TOOLS[@]}"; do
    tool_name="${GO_TOOL_NAMES[$i]}"
    tool_path="${GO_TOOLS[$i]}"
    if command -v "$tool_name" &>/dev/null; then
        log_ok "$tool_name already installed $(which $tool_name)"
    else
        log_info "Installing $tool_name..."
        if go install -v "$tool_path" 2>/dev/null; then
            log_ok "$tool_name installed"
        else
            log_err "$tool_name failed to install"
        fi
    fi
done

# ─── Additional Go tools ───
echo ""
log_info "Installing additional Go tools..."

EXTRA_GO_TOOLS=(
    "github.com/tomnomnom/waybackurls@latest"
    "github.com/lc/gau/v2/cmd/gau@latest"
    "github.com/hahwul/dalfox/v2@latest"
    "github.com/ffuf/ffuf/v2@latest"
    "github.com/tomnomnom/anew@latest"
    "github.com/tomnomnom/qsreplace@latest"
    "github.com/tomnomnom/assetfinder@latest"
    "github.com/tomnomnom/gf@latest"
    "github.com/LukaSikic/subzy@latest"
    "github.com/hakluke/hakrawler@latest"
    "github.com/jaeles-project/gospider@latest"
    "github.com/dwisiswant0/crlfuzz/cmd/crlfuzz@latest"
    "github.com/d3mondev/puredns/v2@latest"
    "github.com/projectdiscovery/cdncheck/cmd/cdncheck@latest"
    "github.com/projectdiscovery/alterx/cmd/alterx@latest"
    "github.com/projectdiscovery/uncover/cmd/uncover@latest"
    "github.com/projectdiscovery/tlsx/cmd/tlsx@latest"
)

EXTRA_TOOL_NAMES=(
    "waybackurls"
    "gau"
    "dalfox"
    "ffuf"
    "anew"
    "qsreplace"
    "assetfinder"
    "gf"
    "subzy"
    "hakrawler"
    "gospider"
    "crlfuzz"
    "puredns"
    "cdncheck"
    "alterx"
    "uncover"
    "tlsx"
)

for i in "${!EXTRA_GO_TOOLS[@]}"; do
    tool_name="${EXTRA_TOOL_NAMES[$i]}"
    tool_path="${EXTRA_GO_TOOLS[$i]}"
    if command -v "$tool_name" &>/dev/null; then
        log_ok "$tool_name already installed"
    else
        log_info "Installing $tool_name..."
        go install -v "$tool_path" 2>/dev/null && log_ok "$tool_name installed" || log_err "$tool_name failed"
    fi
done

# ─── Python security tools ───
echo ""
log_info "Installing Python security tools..."

PIP_TOOLS=(
    "arjun"
    "paramspider"
    "xsstrike"
    "trufflehog"
    "commix"
)

for tool in "${PIP_TOOLS[@]}"; do
    if command -v "$tool" &>/dev/null || pip3 show "$tool" &>/dev/null; then
        log_ok "$tool already installed"
    else
        log_info "Installing $tool..."
        pip3 install --quiet --break-system-packages "$tool" 2>/dev/null || \
        pip3 install --quiet "$tool" 2>/dev/null || log_err "$tool failed"
    fi
done

# ─── GF Patterns (for URL classification) ───
echo ""
log_info "Setting up GF patterns..."
GF_DIR="$HOME/.gf"
if [ ! -d "$GF_DIR" ]; then
    mkdir -p "$GF_DIR"
    git clone --quiet https://github.com/1ndianl33t/Gf-Patterns.git /tmp/gf-patterns 2>/dev/null || true
    cp /tmp/gf-patterns/*.json "$GF_DIR/" 2>/dev/null || true
    rm -rf /tmp/gf-patterns
    log_ok "GF patterns installed to $GF_DIR"
else
    log_ok "GF patterns already exist"
fi

# ─── Nuclei Templates ───
echo ""
log_info "Updating nuclei templates..."
if command -v nuclei &>/dev/null; then
    nuclei -update-templates 2>/dev/null || true
    TEMPLATE_COUNT=$(find ~/nuclei-templates -name "*.yaml" 2>/dev/null | wc -l)
    log_ok "Nuclei templates updated ($TEMPLATE_COUNT templates)"
fi

# ─── interactsh setup (OOB callback server — critical for SSRF/XXE) ───
echo ""
log_info "Setting up interactsh (OOB callback server)..."
if command -v interactsh-client &>/dev/null; then
    log_ok "interactsh-client installed"
    echo ""
    echo -e "${CYAN}  To start an interactsh session:${NC}"
    echo "    interactsh-client -v"
    echo ""
    echo -e "${CYAN}  This gives you a unique callback URL like:${NC}"
    echo "    [INF] c23b2la0kl1krjcrdj10cndmnioyyyyyn.oast.pro"
    echo ""
    echo -e "${CYAN}  Use this URL in SSRF/XXE/RCE payloads to detect OOB callbacks.${NC}"
    echo "    Example: curl https://target.com/api/import?url=http://YOUR_URL_HERE.oast.pro"
    echo ""
else
    log_err "interactsh-client not installed — OOB detection won't work"
fi

# ─── SecLists wordlists ───
echo ""
log_info "Checking SecLists..."
if [ -d "/usr/share/seclists" ]; then
    log_ok "SecLists found at /usr/share/seclists"
elif [ -d "$HOME/SecLists" ]; then
    log_ok "SecLists found at $HOME/SecLists"
else
    log_info "Installing SecLists (this takes a few minutes)..."
    sudo apt-get install -y -qq seclists 2>/dev/null || {
        git clone --depth 1 https://github.com/danielmiessler/SecLists.git "$HOME/SecLists" 2>/dev/null || true
    }
fi

# ─── Ensure Go bin is in PATH persistently ───
echo ""
if [[ ":$PATH:" != *":$GOPATH/bin:"* ]]; then
    echo "export PATH=\$PATH:$GOPATH/bin" >> ~/.bashrc
    echo "export PATH=\$PATH:$GOPATH/bin" >> ~/.zshrc 2>/dev/null || true
    log_ok "Added $GOPATH/bin to PATH in .bashrc"
fi

# ─── Environment variables ───
echo ""
log_info "Setting up environment variables..."
ENV_VARS=(
    "H1_API_TOKEN"
    "CHAOS_API_KEY"
)

for var in "${ENV_VARS[@]}"; do
    if [ -z "${!var:-}" ]; then
        log_warn "$var not set. Add to ~/.bashrc: export $var=\"your-value\""
    else
        log_ok "$var is set"
    fi
done

# ─── Create working directories ───
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
mkdir -p "$SCRIPT_DIR/recon" "$SCRIPT_DIR/findings" "$SCRIPT_DIR/reports" \
         "$SCRIPT_DIR/hunt-memory/sessions" "$SCRIPT_DIR/targets"
log_ok "Working directories created"

# ─── Verification ───
echo ""
echo -e "${BOLD}═══════════════════════════════════════════════${NC}"
echo -e "${BOLD}  Installation Verification${NC}"
echo -e "${BOLD}═══════════════════════════════════════════════${NC}"
echo ""

ALL_TOOLS=(subfinder httpx nuclei katana dnsx naabu ffuf gau waybackurls
           dalfox anew qsreplace assetfinder gf interactsh-client subzy
           nmap sqlmap hakrawler)
INSTALLED=0
MISSING=0

for tool in "${ALL_TOOLS[@]}"; do
    if command -v "$tool" &>/dev/null; then
        log_ok "$tool: $(which $tool)"
        ((INSTALLED++))
    else
        log_err "$tool: NOT FOUND"
        ((MISSING++)) || true
    fi
done

echo ""
echo -e "${BOLD}═══════════════════════════════════════════════${NC}"
echo -e "  Installed: ${GREEN}$INSTALLED${NC} / ${#ALL_TOOLS[@]}"
[ "$MISSING" -gt 0 ] && echo -e "  Missing: ${RED}$MISSING${NC} (check errors above)"
echo -e "${BOLD}═══════════════════════════════════════════════${NC}"

# ─── Claude Code Permissions (auto-approve all commands) ───
echo ""
log_info "Setting up Claude Code permissions..."
CLAUDE_DIR="$(dirname "$0")/.claude"
mkdir -p "$CLAUDE_DIR"
if [ ! -f "$CLAUDE_DIR/settings.json" ]; then
    cat > "$CLAUDE_DIR/settings.json" << 'SETTINGS'
{
  "permissions": {
    "allow": [
      "Bash(*)",
      "Read(*)",
      "Write(*)",
      "Glob(*)",
      "Grep(*)"
    ]
  }
}
SETTINGS
    log_ok "Claude Code permissions set — all commands auto-approved"
else
    log_ok "Claude Code permissions already configured"
fi

# ─── Create required directories ───
mkdir -p "$(dirname "$0")/{recon,findings,reports,targets,hunt-memory/sessions,hunt-memory/monitor}"
log_ok "Directory structure created"

echo ""
echo -e "${BOLD}Quick Start:${NC}"
echo "  1. Set API keys:"
echo "     export H1_API_TOKEN=\"your-hackerone-api-token\""  
echo "     export GITHUB_TOKEN=\"your-github-token\"  # optional"
echo ""
echo "  2. Start Claude Code:"
echo "     claude --dangerously-skip-permissions"
echo ""
echo "  3. Run autonomous hunt:"
echo "     /fullhunt rockstargames"
echo ""
echo "  4. Resume after break:"
echo "     /resume rockstargames"
echo ""
