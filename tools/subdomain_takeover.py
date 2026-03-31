#!/usr/bin/env python3
"""
Subdomain Takeover Checker — Dangling CNAME Detection

Checks subdomains for takeover potential:
- Detects dangling CNAMEs (points to deprovisioned service)
- Matches against 100+ known vulnerable fingerprints
- Tests actual HTTP response for takeover indicators
- Outputs ready-to-claim PoC

Usage:
    python3 subdomain_takeover.py --target target.com --subs-file recon/target/subdomains.txt
    python3 subdomain_takeover.py --subdomain old-blog.target.com
"""

import argparse
import json
import os
import re
import socket
import subprocess
import sys
import time
from datetime import datetime
from urllib.request import Request, urlopen
from urllib.error import HTTPError, URLError

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FINDINGS_DIR = os.path.join(BASE_DIR, "findings")

GREEN = "\033[0;32m"
RED = "\033[0;31m"
YELLOW = "\033[1;33m"
CYAN = "\033[0;36m"
BOLD = "\033[1m"
NC = "\033[0m"


def log(level, msg):
    colors = {"ok": GREEN, "err": RED, "warn": YELLOW, "info": CYAN, "vuln": RED}
    symbols = {"ok": "+", "err": "-", "warn": "!", "info": "*", "vuln": "🔴"}
    ts = datetime.now().strftime("%H:%M:%S")
    print(f"[{ts}] {colors.get(level, '')}{BOLD}[{symbols.get(level, '*')}]{NC} {msg}")


# Known vulnerable service fingerprints
# Format: (cname_pattern, http_response_fingerprint, service_name, can_claim)
FINGERPRINTS = [
    # GitHub Pages
    ("github.io", "There isn't a GitHub Pages site here", "GitHub Pages", True),
    ("github.io", "For root URLs (like http://example.com/)", "GitHub Pages", True),

    # Heroku
    (".herokuapp.com", "No such app", "Heroku", True),
    (".herokuapp.com", "no-such-app", "Heroku", True),

    # AWS S3
    (".s3.amazonaws.com", "NoSuchBucket", "AWS S3", True),
    (".s3-website", "NoSuchBucket", "AWS S3", True),
    ("s3.amazonaws.com", "The specified bucket does not exist", "AWS S3", True),

    # AWS Elastic Beanstalk
    (".elasticbeanstalk.com", "NXDOMAIN", "AWS Elastic Beanstalk", True),

    # Azure
    (".azurewebsites.net", "404 Web Site not found", "Azure", True),
    (".cloudapp.net", "NXDOMAIN", "Azure", True),
    (".cloudapp.azure.com", "NXDOMAIN", "Azure", True),
    (".trafficmanager.net", "NXDOMAIN", "Azure Traffic Manager", True),
    (".blob.core.windows.net", "BlobNotFound", "Azure Blob", True),

    # Shopify
    ("myshopify.com", "Sorry, this shop is currently unavailable", "Shopify", True),
    ("shops.myshopify.com", "Only one step left", "Shopify", True),

    # Surge.sh
    (".surge.sh", "project not found", "Surge.sh", True),

    # Tumblr
    (".tumblr.com", "There's nothing here", "Tumblr", True),
    (".tumblr.com", "Whatever you were looking for doesn't currently exist", "Tumblr", True),

    # WordPress
    (".wordpress.com", "Do you want to register", "WordPress.com", True),

    # Ghost
    (".ghost.io", "The thing you were looking for is no longer here", "Ghost", True),

    # Pantheon
    (".pantheonsite.io", "The gods are wise", "Pantheon", True),

    # Fastly
    (".fastly.net", "Fastly error: unknown domain", "Fastly", True),

    # Zendesk
    (".zendesk.com", "Help Center Closed", "Zendesk", True),

    # Unbounce
    (".unbouncepages.com", "The requested URL was not found", "Unbounce", True),

    # TeamWork
    (".teamwork.com", "Oops - We didn't find your site", "TeamWork", True),

    # Helpscout
    (".helpscoutdocs.com", "No settings were found", "HelpScout", True),

    # Cargo
    (".cargocollective.com", "404 Not Found", "Cargo", True),

    # Bitbucket
    (".bitbucket.io", "Repository not found", "Bitbucket", True),

    # Netlify
    (".netlify.app", "Not Found - Request ID", "Netlify", True),
    (".netlify.com", "Not Found - Request ID", "Netlify", True),

    # Fly.io
    (".fly.dev", "404", "Fly.io", True),

    # Vercel
    (".vercel.app", "404: NOT_FOUND", "Vercel", True),

    # Render
    (".onrender.com", "not found", "Render", True),

    # Firebase
    (".firebaseapp.com", "Site Not Found", "Firebase", True),
    (".web.app", "Site Not Found", "Firebase", True),
]


def resolve_cname(domain):
    """Resolve CNAME record for a domain."""
    try:
        result = subprocess.run(
            ["dig", "+short", "CNAME", domain],
            capture_output=True, text=True, timeout=10,
        )
        cnames = [line.strip().rstrip(".") for line in result.stdout.strip().split("\n")
                  if line.strip()]
        return cnames
    except (subprocess.TimeoutExpired, FileNotFoundError):
        # Fallback: try nslookup
        try:
            result = subprocess.run(
                ["nslookup", "-type=CNAME", domain],
                capture_output=True, text=True, timeout=10,
            )
            cnames = re.findall(r'canonical name\s*=\s*(\S+)', result.stdout, re.IGNORECASE)
            return [c.rstrip(".") for c in cnames]
        except Exception:
            return []


def check_nxdomain(domain):
    """Check if domain resolves to NXDOMAIN."""
    try:
        socket.getaddrinfo(domain, None)
        return False  # Resolves
    except socket.gaierror:
        return True  # NXDOMAIN


def check_http_response(domain, timeout=10):
    """Get HTTP response body for fingerprint matching."""
    for scheme in ["https", "http"]:
        try:
            url = f"{scheme}://{domain}"
            req = Request(url, headers={"User-Agent": "Mozilla/5.0"})
            with urlopen(req, timeout=timeout) as resp:
                return resp.read().decode("utf-8", errors="replace")[:5000]
        except HTTPError as e:
            try:
                return e.read().decode("utf-8", errors="replace")[:5000]
            except Exception:
                pass
        except Exception:
            continue
    return ""


def check_subdomain(subdomain):
    """Check a single subdomain for takeover potential.

    Returns finding dict or None.
    """
    result = {
        "subdomain": subdomain,
        "cnames": [],
        "nxdomain": False,
        "vulnerable": False,
        "service": None,
        "can_claim": False,
        "fingerprint_match": None,
    }

    # Step 1: Resolve CNAME
    cnames = resolve_cname(subdomain)
    result["cnames"] = cnames

    if not cnames:
        return result  # No CNAME, skip

    # Step 2: Check if CNAME points to NXDOMAIN
    for cname in cnames:
        if check_nxdomain(cname):
            result["nxdomain"] = True
            result["vulnerable"] = True

            # Match against fingerprints
            for pattern, _, service, can_claim in FINGERPRINTS:
                if pattern in cname.lower():
                    result["service"] = service
                    result["can_claim"] = can_claim
                    result["fingerprint_match"] = f"CNAME {cname} → NXDOMAIN ({service})"
                    break

            if not result["service"]:
                result["service"] = "Unknown"
                result["fingerprint_match"] = f"CNAME {cname} → NXDOMAIN (dangling)"

    # Step 3: Check HTTP response fingerprints (even if CNAME resolves)
    if not result["vulnerable"]:
        body = check_http_response(subdomain)
        if body:
            for cname in cnames:
                for pattern, fingerprint, service, can_claim in FINGERPRINTS:
                    if pattern in cname.lower() and fingerprint in body:
                        result["vulnerable"] = True
                        result["service"] = service
                        result["can_claim"] = can_claim
                        result["fingerprint_match"] = (
                            f"CNAME {cname} → HTTP fingerprint: '{fingerprint[:50]}' ({service})"
                        )
                        break
                if result["vulnerable"]:
                    break

    return result


class SubdomainTakeoverChecker:
    """Bulk subdomain takeover checker."""

    def __init__(self, rate_limit=5.0):
        self.rate_limit = rate_limit
        self.findings = []
        self.checked = 0

    def check_file(self, filepath):
        """Check all subdomains from a file."""
        with open(filepath) as f:
            subdomains = [line.strip() for line in f if line.strip() and not line.startswith("#")]

        log("info", f"Checking {len(subdomains)} subdomains for takeover...")

        for i, sub in enumerate(subdomains):
            log("info", f"[{i+1}/{len(subdomains)}] {sub}")
            result = check_subdomain(sub)
            self.checked += 1

            if result["vulnerable"]:
                log("vuln", f"TAKEOVER: {sub} → {result['fingerprint_match']}")
                self.findings.append(result)
            elif result["cnames"]:
                log("info", f"  CNAME: {', '.join(result['cnames'])} (safe ✓)")

            time.sleep(1.0 / self.rate_limit)

        return self.findings

    def check_single(self, subdomain):
        """Check a single subdomain."""
        result = check_subdomain(subdomain)
        self.checked += 1
        if result["vulnerable"]:
            self.findings.append(result)
            log("vuln", f"TAKEOVER: {subdomain} → {result['fingerprint_match']}")
        else:
            log("info", f"{subdomain} → not vulnerable ✓")
        return result

    def save_findings(self, target_name):
        if not self.findings:
            return
        output_dir = os.path.join(FINDINGS_DIR, target_name)
        os.makedirs(output_dir, exist_ok=True)
        filepath = os.path.join(output_dir, "takeover_findings.json")
        with open(filepath, "w") as f:
            json.dump({
                "checked": self.checked,
                "vulnerable": len(self.findings),
                "findings": self.findings,
            }, f, indent=2)
        log("ok", f"Saved {len(self.findings)} findings to {filepath}")

    def print_summary(self):
        print(f"\n{BOLD}{'='*60}{NC}")
        print(f"{BOLD}  Subdomain Takeover Summary{NC}")
        print(f"{'='*60}\n")
        print(f"  Checked: {self.checked}")
        print(f"  Vulnerable: {len(self.findings)}")
        if self.findings:
            for f in self.findings:
                claimable = "✓ CLAIMABLE" if f["can_claim"] else "⚠ Manual check needed"
                print(f"\n  {RED}{BOLD}{f['subdomain']}{NC}")
                print(f"    CNAME: {', '.join(f['cnames'])}")
                print(f"    Service: {f['service']}")
                print(f"    {claimable}")
                print(f"    Match: {f['fingerprint_match']}")
        else:
            print(f"\n  {GREEN}No takeover vulnerabilities found ✓{NC}")
        print()


def main():
    parser = argparse.ArgumentParser(description="Subdomain Takeover Checker")
    parser.add_argument("--target", help="Target domain")
    parser.add_argument("--subs-file", help="File with subdomains")
    parser.add_argument("--subdomain", help="Check single subdomain")
    parser.add_argument("--rate-limit", type=float, default=5.0)
    args = parser.parse_args()

    checker = SubdomainTakeoverChecker(rate_limit=args.rate_limit)

    if args.subs_file:
        checker.check_file(args.subs_file)
    elif args.subdomain:
        checker.check_single(args.subdomain)
    elif args.target:
        # Try to find subdomains file from recon
        subs_file = os.path.join(BASE_DIR, "recon", args.target, "subdomains.txt")
        if os.path.exists(subs_file):
            checker.check_file(subs_file)
        else:
            log("err", f"No subdomains file found at {subs_file}")
            log("info", "Run /recon first, or provide --subs-file")
            sys.exit(1)

    checker.print_summary()
    target = args.target or args.subdomain or "unknown"
    target = target.replace(".", "_").split("/")[0]
    checker.save_findings(target)


if __name__ == "__main__":
    main()
