#!/bin/bash
# Update all nuclei template sources for bug bounty hunting
set -euo pipefail

TEMPLATES_DIR="$HOME/nuclei-templates-extra"
mkdir -p "$TEMPLATES_DIR"

echo "[*] Updating official nuclei templates..."
nuclei -update-templates

echo "[*] Cloning/updating community template collections..."

# Missing CVEs not yet in official repo (weekly updated, BB-focused)
git -C "$TEMPLATES_DIR/missing-cves" pull 2>/dev/null || \
  git clone https://github.com/nuclei-collections/missing-cve-nuclei-templates.git "$TEMPLATES_DIR/missing-cves"

# Custom BB-focused templates
git -C "$TEMPLATES_DIR/custom-kayala" pull 2>/dev/null || \
  git clone https://github.com/0xKayala/Custom-Nuclei-Templates.git "$TEMPLATES_DIR/custom-kayala"

# Saimonkabir BB automation templates
git -C "$TEMPLATES_DIR/saimonkabir" pull 2>/dev/null || \
  git clone https://github.com/Saimonkabir/Nuclei-Templates.git "$TEMPLATES_DIR/saimonkabir"

# Source code analysis templates (secrets, config leaks, debug endpoints)
git -C "$TEMPLATES_DIR/source-code" pull 2>/dev/null || \
  git clone https://github.com/adibarsyad/nuclei-jsp-source-code-review.git "$TEMPLATES_DIR/source-code"

echo "[*] Template counts:"
echo "  Official: $(find ~/.local/nuclei-templates -name '*.yaml' 2>/dev/null | wc -l)"
echo "  Missing CVEs: $(find $TEMPLATES_DIR/missing-cves -name '*.yaml' 2>/dev/null | wc -l)"
echo "  Custom: $(find $TEMPLATES_DIR/custom-kayala -name '*.yaml' 2>/dev/null | wc -l)"
echo "  Total extra: $(find $TEMPLATES_DIR -name '*.yaml' 2>/dev/null | wc -l)"
echo ""
echo "[*] Usage: nuclei -u target.com -t ~/nuclei-templates-extra/"
echo "[*] Or combine: nuclei -u target.com -t ~/nuclei-templates-extra/ -tags cve,rce,sqli"
