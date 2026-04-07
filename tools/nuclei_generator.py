#!/usr/bin/env python3
"""
Nuclei Template Generator — Auto-generate nuclei templates from program intel.

Creates custom nuclei templates based on:
  - Detected tech stack (framework-specific checks)
  - Previously disclosed reports on the program
  - Recon findings (exposed paths, config files)
  - Common misconfig patterns for the identified infrastructure

Usage:
    python3 nuclei_generator.py --target target.com --recon-dir recon/target.com
    python3 nuclei_generator.py --target target.com --tech laravel spring
"""

import argparse
import json
import os
import sys
from datetime import datetime

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TEMPLATES_DIR = os.path.join(BASE_DIR, "nuclei-templates", "generated")

GREEN = "\033[0;32m"
RED = "\033[0;31m"
YELLOW = "\033[1;33m"
CYAN = "\033[0;36m"
BOLD = "\033[1m"
NC = "\033[0m"

def log(level, msg):
    colors = {"ok": GREEN, "err": RED, "warn": YELLOW, "info": CYAN}
    symbols = {"ok": "+", "err": "-", "warn": "!", "info": "*"}
    print(f"{colors.get(level, '')}{BOLD}[{symbols.get(level, '*')}]{NC} {msg}")

# Template definitions by tech/vuln class
TEMPLATE_DEFS = {
    "laravel-debug": {
        "tech": ["laravel", "php"],
        "template": """id: {target}-laravel-debug
info:
  name: Laravel Debug Mode Enabled - {target}
  severity: high
  tags: misconfig,laravel,debug
  description: Laravel debug mode exposes stack traces, env vars, and DB credentials.
http:
  - method: GET
    path:
      - "{{{{BaseURL}}}}/_ignition/health-check"
      - "{{{{BaseURL}}}}/_debugbar/open"
      - "{{{{BaseURL}}}}/telescope"
    matchers-condition: or
    matchers:
      - type: word
        words: ["Laravel", "Ignition", "debugbar"]
      - type: status
        status: [200]
"""},
    "spring-actuator": {
        "tech": ["spring", "java"],
        "template": """id: {target}-spring-actuator
info:
  name: Spring Actuator Exposed - {target}
  severity: high
  tags: misconfig,spring,actuator
  description: Spring Actuator exposes heapdump, env vars, and service mappings.
http:
  - method: GET
    path:
      - "{{{{BaseURL}}}}/actuator"
      - "{{{{BaseURL}}}}/actuator/env"
      - "{{{{BaseURL}}}}/actuator/heapdump"
      - "{{{{BaseURL}}}}/actuator/mappings"
      - "{{{{BaseURL}}}}/actuator/configprops"
    matchers-condition: and
    matchers:
      - type: status
        status: [200]
      - type: word
        words: ["_links", "self", "heapdump", "beans"]
        condition: or
"""},
    "graphql-introspection": {
        "tech": ["graphql"],
        "template": """id: {target}-graphql-introspection
info:
  name: GraphQL Introspection Enabled - {target}
  severity: medium
  tags: misconfig,graphql,introspection
  description: GraphQL introspection exposes the entire schema including mutations.
http:
  - method: POST
    path:
      - "{{{{BaseURL}}}}/graphql"
      - "{{{{BaseURL}}}}/api/graphql"
      - "{{{{BaseURL}}}}/graphql/v1"
    headers:
      Content-Type: application/json
    body: '{{"query":"{{__schema{{types{{name fields{{name}}}}}}}}}"}}'
    matchers-condition: and
    matchers:
      - type: status
        status: [200]
      - type: word
        words: ["__schema", "types", "fields"]
"""},
    "wordpress-users": {
        "tech": ["wordpress"],
        "template": """id: {target}-wp-user-enum
info:
  name: WordPress User Enumeration - {target}
  severity: medium
  tags: wordpress,enum
  description: WordPress REST API exposes usernames via /wp-json/wp/v2/users.
http:
  - method: GET
    path:
      - "{{{{BaseURL}}}}/wp-json/wp/v2/users"
      - "{{{{BaseURL}}}}/?author=1"
    matchers-condition: and
    matchers:
      - type: status
        status: [200, 301]
      - type: word
        words: ["slug", "name", "author"]
        condition: or
"""},
    "exposed-env": {
        "tech": ["*"],
        "template": """id: {target}-exposed-env
info:
  name: Exposed Environment File - {target}
  severity: critical
  tags: exposure,env,credentials
  description: Environment file exposed with potential credentials.
http:
  - method: GET
    path:
      - "{{{{BaseURL}}}}/.env"
      - "{{{{BaseURL}}}}/.env.local"
      - "{{{{BaseURL}}}}/.env.production"
      - "{{{{BaseURL}}}}/.env.backup"
      - "{{{{BaseURL}}}}/env.js"
      - "{{{{BaseURL}}}}/app_env.js"
    matchers-condition: and
    matchers:
      - type: status
        status: [200]
      - type: word
        words: ["DB_PASSWORD", "API_KEY", "SECRET", "AWS_", "MONGO"]
        condition: or
"""},
    "git-exposed": {
        "tech": ["*"],
        "template": """id: {target}-git-exposed
info:
  name: Exposed Git Repository - {target}
  severity: high
  tags: exposure,git
  description: Git repository metadata exposed — source code download possible.
http:
  - method: GET
    path:
      - "{{{{BaseURL}}}}/.git/HEAD"
      - "{{{{BaseURL}}}}/.git/config"
    matchers-condition: and
    matchers:
      - type: status
        status: [200]
      - type: word
        words: ["ref: refs/", "[core]"]
        condition: or
"""},
    "idor-api": {
        "tech": ["*"],
        "template": """id: {target}-idor-api-numeric
info:
  name: Potential IDOR on Numeric ID Endpoints - {target}
  severity: info
  tags: idor,api
  description: API endpoints with numeric IDs — manual IDOR testing recommended.
http:
  - method: GET
    path:
      - "{{{{BaseURL}}}}/api/v1/users/1"
      - "{{{{BaseURL}}}}/api/v2/users/1"
      - "{{{{BaseURL}}}}/api/users/1"
      - "{{{{BaseURL}}}}/api/v1/accounts/1"
      - "{{{{BaseURL}}}}/api/v1/orders/1"
    matchers-condition: and
    matchers:
      - type: status
        status: [200]
      - type: word
        words: ["id", "email", "name", "user"]
        condition: or
"""},
    "cors-misconfig": {
        "tech": ["*"],
        "template": """id: {target}-cors-wildcard
info:
  name: CORS Misconfiguration - {target}
  severity: medium
  tags: cors,misconfig
  description: CORS allows arbitrary origins — potential data theft.
http:
  - method: GET
    path:
      - "{{{{BaseURL}}}}/api/v1/user"
      - "{{{{BaseURL}}}}/api/me"
      - "{{{{BaseURL}}}}/api/profile"
    headers:
      Origin: https://evil.com
    matchers:
      - type: word
        part: header
        words: ["Access-Control-Allow-Origin: https://evil.com"]
"""},
}

class NucleiGenerator:
    def __init__(self, target=""):
        self.target = target
        self.out_dir = os.path.join(TEMPLATES_DIR, target)
        os.makedirs(self.out_dir, exist_ok=True)

    def _detect_tech(self, recon_dir=None):
        """Detect tech from recon data."""
        techs = set()
        if recon_dir:
            prof = os.path.join(recon_dir, "tech_profile.json")
            if os.path.exists(prof):
                try:
                    with open(prof) as f:
                        data = json.load(f)
                    for t in data.get("technologies", []):
                        techs.add(t.lower())
                except: pass
            # Also check httpx output for tech
            httpx = os.path.join(recon_dir, "live", "httpx_full.txt")
            if os.path.exists(httpx):
                try:
                    with open(httpx) as f:
                        content = f.read().lower()
                    for t in ("laravel","django","express","spring","wordpress",
                              "rails","nextjs","graphql","react","angular","vue"):
                        if t in content: techs.add(t)
                except: pass
        return techs

    def generate(self, tech_stack=None, recon_dir=None):
        """Generate nuclei templates based on tech stack."""
        if not tech_stack:
            tech_stack = self._detect_tech(recon_dir)
        tech_stack = {t.lower() for t in tech_stack}

        generated = []
        for tpl_id, tpl_def in TEMPLATE_DEFS.items():
            # Check if template applies to this tech
            tpl_techs = [t.lower() for t in tpl_def["tech"]]
            if "*" in tpl_techs or tech_stack & set(tpl_techs):
                content = tpl_def["template"].format(target=self.target)
                fname = f"{tpl_id}.yaml"
                fpath = os.path.join(self.out_dir, fname)
                with open(fpath, "w") as f:
                    f.write(content)
                generated.append(fname)
                log("ok", f"Generated: {fname}")

        # Generate IDOR templates from recon API endpoints
        if recon_dir:
            api_file = os.path.join(recon_dir, "urls", "api_endpoints.txt")
            if os.path.exists(api_file):
                self._generate_idor_templates(api_file)

        log("ok", f"Generated {len(generated)} templates in {self.out_dir}")
        return generated

    def _generate_idor_templates(self, api_file):
        """Generate IDOR probe templates from discovered API endpoints."""
        try:
            with open(api_file) as f:
                endpoints = [l.strip() for l in f if l.strip()][:20]
        except: return

        if not endpoints: return

        paths = []
        for ep in endpoints:
            from urllib.parse import urlparse
            path = urlparse(ep).path
            if path: paths.append(f'      - "{{{{{{{{BaseURL}}}}}}}}{path}"')

        if not paths: return

        content = f"""id: {self.target}-idor-discovered-endpoints
info:
  name: IDOR Probe on Discovered API Endpoints - {self.target}
  severity: info
  tags: idor,api,custom
  description: Probing discovered API endpoints for IDOR potential.
http:
  - method: GET
    path:
{chr(10).join(paths[:15])}
    matchers-condition: and
    matchers:
      - type: status
        status: [200]
      - type: word
        words: ["id", "email", "user", "data", "account"]
        condition: or
"""
        fpath = os.path.join(self.out_dir, "idor-discovered.yaml")
        with open(fpath, "w") as f:
            f.write(content)
        log("ok", "Generated: idor-discovered.yaml")

def main():
    p = argparse.ArgumentParser(description="Nuclei Template Generator")
    p.add_argument("--target", required=True)
    p.add_argument("--recon-dir", help="Recon data directory")
    p.add_argument("--tech", nargs="*", help="Tech stack")
    args = p.parse_args()

    gen = NucleiGenerator(args.target)
    gen.generate(tech_stack=set(args.tech) if args.tech else None,
                 recon_dir=args.recon_dir)

if __name__ == "__main__": main()
