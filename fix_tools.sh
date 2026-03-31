#!/bin/bash
# =============================================================================
# Fix script for tools that failed during initial install
# Run: chmod +x fix_tools.sh && ./fix_tools.sh
# =============================================================================

set -uo pipefail

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
echo -e "${BOLD}║   Fixing Failed Tool Installations           ║${NC}"
echo -e "${BOLD}╚══════════════════════════════════════════════╝${NC}"
echo ""

# ─── Fix 1: katana + naabu need libpcap-dev ───
log_info "Installing libpcap-dev (needed by katana + naabu)..."
sudo apt-get install -y libpcap-dev 2>/dev/null && log_ok "libpcap-dev installed" || log_warn "libpcap-dev may need manual install"

echo ""
log_info "Installing katana..."
CGO_ENABLED=1 go install github.com/projectdiscovery/katana/cmd/katana@latest 2>&1 | tail -1
if command -v katana &>/dev/null || [ -f "$HOME/go/bin/katana" ]; then
    log_ok "katana installed: $(which katana 2>/dev/null || echo $HOME/go/bin/katana)"
else
    log_err "katana still failed — try: sudo apt install katana"
fi

echo ""
log_info "Installing naabu..."
CGO_ENABLED=1 go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest 2>&1 | tail -1
if command -v naabu &>/dev/null || [ -f "$HOME/go/bin/naabu" ]; then
    log_ok "naabu installed: $(which naabu 2>/dev/null || echo $HOME/go/bin/naabu)"
else
    log_err "naabu still failed — try: sudo apt install naabu"
fi

# ─── Fix 2: subzy — repo moved ───
echo ""
log_info "Installing subzy..."
go install github.com/PentestPad/subzy@latest 2>&1 | tail -1
if command -v subzy &>/dev/null || [ -f "$HOME/go/bin/subzy" ]; then
    log_ok "subzy installed"
else
    log_err "subzy still failed"
fi

# ─── Fix 3: arjun (pip package name is 'arjun') ───
echo ""
log_info "Installing arjun..."
pip3 install --break-system-packages arjun 2>/dev/null || \
pipx install arjun 2>/dev/null || \
{
    git clone --quiet https://github.com/s0md3v/Arjun.git /tmp/arjun 2>/dev/null
    cd /tmp/arjun && pip3 install --break-system-packages . 2>/dev/null
    cd - >/dev/null
}
if command -v arjun &>/dev/null || python3 -c "import arjun" 2>/dev/null; then
    log_ok "arjun installed"
else
    log_err "arjun failed — install manually: pip3 install arjun"
fi

# ─── Fix 4: paramspider ───
echo ""
log_info "Installing paramspider..."
pip3 install --break-system-packages paramspider 2>/dev/null || \
{
    git clone --quiet https://github.com/devanshbatham/paramspider.git /tmp/paramspider 2>/dev/null
    cd /tmp/paramspider && pip3 install --break-system-packages . 2>/dev/null
    cd - >/dev/null
}
if command -v paramspider &>/dev/null; then
    log_ok "paramspider installed"
else
    log_err "paramspider failed — install manually: pip3 install paramspider"
fi

# ─── Fix 5: xsstrike ───
echo ""
log_info "Installing XSStrike..."
git clone --quiet https://github.com/s0md3v/XSStrike.git /opt/XSStrike 2>/dev/null || true
if [ -d "/opt/XSStrike" ]; then
    cd /opt/XSStrike && pip3 install --break-system-packages -r requirements.txt 2>/dev/null
    # Create a wrapper script
    cat > /usr/local/bin/xsstrike << 'EOF'
#!/bin/bash
python3 /opt/XSStrike/xsstrike.py "$@"
EOF
    sudo chmod +x /usr/local/bin/xsstrike 2>/dev/null || chmod +x /usr/local/bin/xsstrike 2>/dev/null
    cd - >/dev/null
    log_ok "XSStrike installed to /opt/XSStrike"
else
    log_err "XSStrike clone failed"
fi

# ─── Fix 6: trufflehog (Go binary, not pip) ───
echo ""
log_info "Installing trufflehog..."
# trufflehog is distributed as a Go binary, not a pip package
curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh | sudo sh -s -- -b /usr/local/bin 2>/dev/null
if command -v trufflehog &>/dev/null; then
    log_ok "trufflehog installed: $(which trufflehog)"
else
    # Fallback: try Go install
    go install github.com/trufflesecurity/trufflehog/v3@latest 2>/dev/null
    if [ -f "$HOME/go/bin/trufflehog" ]; then
        log_ok "trufflehog installed via Go"
    else
        log_err "trufflehog failed — install manually from https://github.com/trufflesecurity/trufflehog/releases"
    fi
fi

# ─── Fix 7: commix ───
echo ""
log_info "Installing commix..."
# commix is usually in Kali repos
sudo apt-get install -y commix 2>/dev/null
if command -v commix &>/dev/null; then
    log_ok "commix installed: $(which commix)"
else
    # Fallback: clone from GitHub
    git clone --quiet https://github.com/commixproject/commix.git /opt/commix 2>/dev/null || true
    if [ -d "/opt/commix" ]; then
        cat > /usr/local/bin/commix << 'EOF'
#!/bin/bash
python3 /opt/commix/commix.py "$@"
EOF
        sudo chmod +x /usr/local/bin/commix 2>/dev/null || chmod +x /usr/local/bin/commix 2>/dev/null
        log_ok "commix installed to /opt/commix"
    else
        log_err "commix failed"
    fi
fi

# ─── Ensure Go bin is in PATH ───
echo ""
if ! echo "$PATH" | grep -q "$HOME/go/bin"; then
    echo 'export PATH=$PATH:$HOME/go/bin' >> ~/.bashrc
    export PATH=$PATH:$HOME/go/bin
    log_ok "Added ~/go/bin to PATH"
fi

# ─── Verify all fixed tools ───
echo ""
echo -e "${BOLD}═══════════════════════════════════════════════${NC}"
echo -e "${BOLD}  Verification${NC}"
echo -e "${BOLD}═══════════════════════════════════════════════${NC}"

TOOLS=(katana naabu subzy arjun paramspider trufflehog commix)
FIXED=0
STILL_BROKEN=0

for tool in "${TOOLS[@]}"; do
    if command -v "$tool" &>/dev/null; then
        log_ok "$tool: $(which $tool)"
        ((FIXED++))
    else
        log_err "$tool: NOT FOUND"
        ((STILL_BROKEN++)) || true
    fi
done

# Check XSStrike separately (it's a python script)
if [ -f "/opt/XSStrike/xsstrike.py" ]; then
    log_ok "xsstrike: /opt/XSStrike/xsstrike.py"
    ((FIXED++))
else
    log_err "xsstrike: NOT FOUND"
    ((STILL_BROKEN++)) || true
fi

echo ""
echo -e "  Fixed: ${GREEN}$FIXED${NC} / 8"
[ "$STILL_BROKEN" -gt 0 ] && echo -e "  Still broken: ${RED}$STILL_BROKEN${NC}"
echo ""
