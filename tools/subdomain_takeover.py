#!/usr/bin/env python3
"""
subdomain_takeover.py — Subdomain Takeover Detection

Detects dangling CNAMEs pointing to unclaimed services (S3, Heroku,
GitHub Pages, Azure, etc.). Easy $1K-$10K wins.

Usage:
    from subdomain_takeover import SubdomainTakeover
    scanner = SubdomainTakeover()
    results = scanner.scan_domain("target.com")
"""
import json
import os
import re
import socket
import subprocess
import time
from pathlib import Path

try:
    import requests
except ImportError:
    requests = None

# ── Fingerprints for takeover-able services ────────────────────────────────────

TAKEOVER_FINGERPRINTS = {
    "aws_s3": {
        "cnames": [".s3.amazonaws.com", ".s3-website"],
        "fingerprint": ["NoSuchBucket", "The specified bucket does not exist"],
        "severity": "HIGH",
        "service": "AWS S3",
    },
    "github_pages": {
        "cnames": [".github.io", "github.map.fastly.net"],
        "fingerprint": ["There isn't a GitHub Pages site here", "For root URLs"],
        "severity": "HIGH",
        "service": "GitHub Pages",
    },
    "heroku": {
        "cnames": [".herokuapp.com", ".herokussl.com", ".herokudns.com"],
        "fingerprint": ["No such app", "no-such-app", "herokucdn.com/error-pages"],
        "severity": "HIGH",
        "service": "Heroku",
    },
    "azure": {
        "cnames": [".azurewebsites.net", ".cloudapp.net", ".azure-api.net",
                   ".azurefd.net", ".blob.core.windows.net", ".trafficmanager.net"],
        "fingerprint": ["404 Web Site not found", "InvalidQueryParameterValue"],
        "severity": "HIGH",
        "service": "Azure",
    },
    "shopify": {
        "cnames": [".myshopify.com"],
        "fingerprint": ["Sorry, this shop is currently unavailable",
                       "Only one step left"],
        "severity": "MEDIUM",
        "service": "Shopify",
    },
    "fastly": {
        "cnames": [".fastly.net", ".fastlylb.net"],
        "fingerprint": ["Fastly error: unknown domain"],
        "severity": "HIGH",
        "service": "Fastly",
    },
    "pantheon": {
        "cnames": [".pantheonsite.io"],
        "fingerprint": ["404 error unknown site", "The gods are wise"],
        "severity": "HIGH",
        "service": "Pantheon",
    },
    "zendesk": {
        "cnames": [".zendesk.com"],
        "fingerprint": ["Help Center Closed", "this help center no longer exists"],
        "severity": "MEDIUM",
        "service": "Zendesk",
    },
    "netlify": {
        "cnames": [".netlify.app", ".netlify.com"],
        "fingerprint": ["Not Found - Request ID"],
        "severity": "HIGH",
        "service": "Netlify",
    },
    "wordpress": {
        "cnames": [".wordpress.com"],
        "fingerprint": ["Do you want to register"],
        "severity": "MEDIUM",
        "service": "WordPress.com",
    },
    "ghost": {
        "cnames": [".ghost.io"],
        "fingerprint": ["The thing you were looking for is no longer here"],
        "severity": "MEDIUM",
        "service": "Ghost",
    },
    "bitbucket": {
        "cnames": [".bitbucket.io"],
        "fingerprint": ["Repository not found"],
        "severity": "HIGH",
        "service": "Bitbucket",
    },
    "tumblr": {
        "cnames": [".tumblr.com"],
        "fingerprint": ["There's nothing here", "Whatever you were looking for"],
        "severity": "MEDIUM",
        "service": "Tumblr",
    },
    "surge": {
        "cnames": [".surge.sh"],
        "fingerprint": ["project not found"],
        "severity": "MEDIUM",
        "service": "Surge.sh",
    },
    "unbounce": {
        "cnames": [".unbouncepages.com"],
        "fingerprint": ["The requested URL was not found"],
        "severity": "MEDIUM",
        "service": "Unbounce",
    },
}


class SubdomainTakeover:
    """Detect subdomain takeover vulnerabilities."""

    def __init__(self):
        self.findings = []
        self.session = requests.Session() if requests else None
        if self.session:
            self.session.verify = False
            import urllib3
            urllib3.disable_warnings()

    def get_cname(self, subdomain: str) -> str:
        """Resolve CNAME record for a subdomain."""
        try:
            result = subprocess.run(
                ["dig", "+short", "CNAME", subdomain],
                capture_output=True, text=True, timeout=10)
            cname = result.stdout.strip().rstrip(".")
            return cname if cname else ""
        except Exception:
            pass
        try:
            result = subprocess.run(
                ["nslookup", "-type=CNAME", subdomain],
                capture_output=True, text=True, timeout=10)
            match = re.search(r"canonical name\s*=\s*(\S+)", result.stdout)
            if match:
                return match.group(1).rstrip(".")
        except Exception:
            pass
        return ""

    def check_nxdomain(self, hostname: str) -> bool:
        """Check if hostname has NXDOMAIN."""
        try:
            socket.getaddrinfo(hostname, None)
            return False
        except socket.gaierror:
            return True

    def check_takeover(self, subdomain: str, cname: str) -> dict:
        """Check if a CNAME is vulnerable to takeover."""
        result = {"subdomain": subdomain, "cname": cname,
                  "vulnerable": False, "service": "", "evidence": ""}

        matched_service = None
        for sn, svc in TAKEOVER_FINGERPRINTS.items():
            if any(p in cname.lower() for p in svc["cnames"]):
                matched_service = svc
                result["service"] = svc["service"]
                break

        if not matched_service:
            return result

        if self.check_nxdomain(cname):
            result["vulnerable"] = True
            result["evidence"] = f"CNAME {cname} returns NXDOMAIN"
            result["severity"] = matched_service["severity"]
            return result

        for scheme in ["https", "http"]:
            try:
                resp = self.session.get(f"{scheme}://{subdomain}",
                                       timeout=8, allow_redirects=True)
                for fp in matched_service["fingerprint"]:
                    if fp.lower() in resp.text.lower():
                        result["vulnerable"] = True
                        result["evidence"] = f"Fingerprint: '{fp}'"
                        result["severity"] = matched_service["severity"]
                        return result
            except Exception:
                continue
        return result

    def scan_domain(self, domain: str, subdomains: list[str] = None) -> dict:
        """Scan all subdomains for takeover possibilities."""
        results = {"domain": domain, "total_checked": 0,
                   "vulnerable": [], "dangling": []}

        if not subdomains:
            recon_file = Path(f"recon/{domain}/subdomains.txt")
            if recon_file.exists():
                subdomains = [l.strip() for l in
                             recon_file.read_text().splitlines() if l.strip()]
            else:
                try:
                    proc = subprocess.run(["subfinder", "-d", domain, "-silent"],
                                         capture_output=True, text=True, timeout=120)
                    subdomains = proc.stdout.strip().splitlines()
                except Exception:
                    subdomains = [domain]

        for sub in subdomains:
            results["total_checked"] += 1
            cname = self.get_cname(sub)
            if not cname or domain in cname:
                continue
            check = self.check_takeover(sub, cname)
            if check["vulnerable"]:
                results["vulnerable"].append(check)
                self.findings.append(check)
            elif check["service"]:
                results["dangling"].append(check)
            time.sleep(0.3)
        return results

    def save_findings(self, target: str) -> None:
        out_dir = Path(f"findings/{target}/takeover")
        out_dir.mkdir(parents=True, exist_ok=True)
        if self.findings:
            out_file = out_dir / f"takeover_{int(time.time())}.json"
            out_file.write_text(json.dumps(self.findings, indent=2, default=str))
