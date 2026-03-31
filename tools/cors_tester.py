#!/usr/bin/env python3
"""
CORS Tester — Advanced CORS Misconfiguration Testing

Tests:
- Origin reflection (mirrors any Origin header → credential theft)
- Null origin acceptance (sandboxed iframe bypass)
- Subdomain wildcard (*.target.com accepted → XSS on any subdomain = ATO)
- Third-party origin acceptance (target trusts attacker.com)
- Pre-flight bypass (non-standard headers without OPTIONS)
- Credentials: include testing

Usage:
    python3 cors_tester.py --target https://api.target.com/user/profile
    python3 cors_tester.py --target https://api.target.com/user/profile --domain target.com
"""

import argparse
import json
import os
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


def cors_request(url, origin, timeout=10):
    """Send request with Origin header and capture CORS headers."""
    headers = {
        "Origin": origin,
        "User-Agent": "Mozilla/5.0",
        "Accept": "*/*",
    }
    try:
        req = Request(url, headers=headers)
        with urlopen(req, timeout=timeout) as resp:
            resp_headers = dict(resp.headers)
            return {
                "status": resp.status,
                "acao": resp_headers.get("Access-Control-Allow-Origin", ""),
                "acac": resp_headers.get("Access-Control-Allow-Credentials", ""),
                "acah": resp_headers.get("Access-Control-Allow-Headers", ""),
                "acam": resp_headers.get("Access-Control-Allow-Methods", ""),
                "all_headers": resp_headers,
                "body_size": len(resp.read()),
            }
    except HTTPError as e:
        resp_headers = dict(e.headers) if e.headers else {}
        return {
            "status": e.code,
            "acao": resp_headers.get("Access-Control-Allow-Origin", ""),
            "acac": resp_headers.get("Access-Control-Allow-Credentials", ""),
            "acah": resp_headers.get("Access-Control-Allow-Headers", ""),
            "acam": resp_headers.get("Access-Control-Allow-Methods", ""),
            "all_headers": resp_headers,
            "body_size": 0,
        }
    except Exception:
        return {"status": 0, "acao": "", "acac": "", "acah": "", "acam": "",
                "all_headers": {}, "body_size": 0}


class CORSTester:
    """CORS misconfiguration tester."""

    def __init__(self, target_url, domain=None, rate_limit=3.0):
        self.url = target_url
        self.domain = domain or self._extract_domain(target_url)
        self.rate_limit = rate_limit
        self.findings = []

    def _extract_domain(self, url):
        from urllib.parse import urlparse
        parsed = urlparse(url)
        parts = parsed.hostname.split(".")
        if len(parts) >= 2:
            return ".".join(parts[-2:])
        return parsed.hostname

    def _sleep(self):
        if self.rate_limit > 0:
            time.sleep(1.0 / self.rate_limit)

    def _add_finding(self, vuln_type, severity, details, origin, response):
        finding = {
            "type": vuln_type,
            "severity": severity,
            "details": details,
            "tested_origin": origin,
            "acao": response.get("acao"),
            "acac": response.get("acac"),
            "found_at": datetime.now().isoformat(),
        }
        self.findings.append(finding)
        log("vuln", f"[{severity}] {vuln_type}: {details[:80]}")

    def test_all(self):
        """Run all CORS tests."""
        log("info", f"Testing CORS on {self.url} (domain: {self.domain})")
        print()

        self._test_origin_reflection()
        self._test_null_origin()
        self._test_subdomain_wildcard()
        self._test_third_party()
        self._test_prefix_suffix()
        self._test_special_chars()

        return self.findings

    def _test_origin_reflection(self):
        """Test if any Origin is reflected back (most dangerous)."""
        log("info", "Test 1: Origin reflection...")
        evil = "https://evil.com"
        resp = cors_request(self.url, evil)
        self._sleep()

        if resp["acao"] == evil:
            creds = resp["acac"].lower() == "true"
            severity = "CRITICAL" if creds else "HIGH"
            self._add_finding(
                "CORS_ORIGIN_REFLECTION",
                severity,
                f"Any Origin is reflected. Credentials: {creds}. "
                + ("Attacker can steal auth tokens via evil.com." if creds
                   else "Data readable cross-origin but no cookies sent."),
                evil, resp,
            )
        else:
            log("info", f"  Origin 'evil.com' → ACAO: '{resp['acao']}' (not reflected ✓)")

    def _test_null_origin(self):
        """Test if null origin is accepted (iframe sandbox bypass)."""
        log("info", "Test 2: Null origin...")
        resp = cors_request(self.url, "null")
        self._sleep()

        if resp["acao"] == "null":
            creds = resp["acac"].lower() == "true"
            severity = "HIGH" if creds else "MEDIUM"
            self._add_finding(
                "CORS_NULL_ORIGIN",
                severity,
                f"Null origin accepted. Credentials: {creds}. "
                f"Exploitable via sandboxed iframe: "
                f"<iframe sandbox='allow-scripts' src='data:text/html,...'>",
                "null", resp,
            )
        else:
            log("info", f"  Null origin → ACAO: '{resp['acao']}' (rejected ✓)")

    def _test_subdomain_wildcard(self):
        """Test if arbitrary subdomains of target are accepted."""
        log("info", "Test 3: Subdomain wildcard...")

        subdomains = [
            f"https://evil.{self.domain}",
            f"https://xss.{self.domain}",
            f"https://attacker.{self.domain}",
            f"https://anything-here.{self.domain}",
        ]

        for origin in subdomains:
            resp = cors_request(self.url, origin)
            self._sleep()

            if resp["acao"] == origin:
                creds = resp["acac"].lower() == "true"
                severity = "HIGH" if creds else "MEDIUM"
                self._add_finding(
                    "CORS_SUBDOMAIN_WILDCARD",
                    severity,
                    f"Arbitrary subdomains accepted (*.{self.domain}). "
                    f"XSS on ANY subdomain → steal auth tokens. Credentials: {creds}.",
                    origin, resp,
                )
                return

        log("info", f"  Subdomain wildcard not accepted ✓")

    def _test_third_party(self):
        """Test if specific third-party origins are trusted."""
        log("info", "Test 4: Third-party origins...")

        origins = [
            "https://localhost",
            "https://localhost:8080",
            "http://127.0.0.1",
            f"https://{self.domain}.evil.com",
            f"https://evil{self.domain}",
            "https://jsbin.com",
            "https://codepen.io",
            "https://jsfiddle.net",
        ]

        for origin in origins:
            resp = cors_request(self.url, origin)
            self._sleep()

            if resp["acao"] == origin:
                creds = resp["acac"].lower() == "true"
                severity = "HIGH" if creds else "MEDIUM"
                self._add_finding(
                    "CORS_THIRD_PARTY_TRUSTED",
                    severity,
                    f"Third-party origin trusted: {origin}. Credentials: {creds}.",
                    origin, resp,
                )

    def _test_prefix_suffix(self):
        """Test prefix/suffix bypass techniques."""
        log("info", "Test 5: Prefix/suffix bypass...")

        bypasses = [
            f"https://{self.domain}.evil.com",       # suffix
            f"https://evil.com.{self.domain}",        # prefix
            f"https://{self.domain}evil.com",         # no dot
            f"https://evil{self.domain}",             # prepend
            f"https://subdomain.{self.domain}%60.evil.com",  # backtick
        ]

        for origin in bypasses:
            resp = cors_request(self.url, origin)
            self._sleep()

            if resp["acao"] == origin:
                creds = resp["acac"].lower() == "true"
                self._add_finding(
                    "CORS_REGEX_BYPASS",
                    "HIGH",
                    f"CORS regex bypass: {origin} accepted. Weak domain validation.",
                    origin, resp,
                )

    def _test_special_chars(self):
        """Test special character injection in origin."""
        log("info", "Test 6: Special characters...")

        specials = [
            f"https://{self.domain}%0d%0a",
            f"https://{self.domain}%09",
            f"https://{self.domain}%00",
        ]

        for origin in specials:
            resp = cors_request(self.url, origin)
            self._sleep()

            if resp["acao"] and self.domain in resp["acao"]:
                self._add_finding(
                    "CORS_SPECIAL_CHAR",
                    "MEDIUM",
                    f"Special character in origin accepted: {origin}",
                    origin, resp,
                )

    def save_findings(self, target_name):
        if not self.findings:
            return
        output_dir = os.path.join(FINDINGS_DIR, target_name)
        os.makedirs(output_dir, exist_ok=True)
        filepath = os.path.join(output_dir, "cors_findings.json")
        with open(filepath, "w") as f:
            json.dump({"findings": self.findings, "url": self.url}, f, indent=2)
        log("ok", f"Saved {len(self.findings)} findings to {filepath}")

    def print_summary(self):
        print(f"\n{BOLD}{'='*60}{NC}")
        print(f"{BOLD}  CORS Test Summary{NC}")
        print(f"{'='*60}\n")
        if self.findings:
            for f in self.findings:
                color = RED if f["severity"] in ("CRITICAL", "HIGH") else YELLOW
                print(f"  {color}[{f['severity']}] {f['type']}{NC}")
                print(f"    Origin: {f['tested_origin']}")
                print(f"    ACAO: {f['acao']} | Credentials: {f['acac']}")
        else:
            print(f"  {GREEN}No CORS misconfigurations found ✓{NC}")
        print()


def main():
    parser = argparse.ArgumentParser(description="CORS Misconfiguration Tester")
    parser.add_argument("--target", required=True, help="Target URL")
    parser.add_argument("--domain", help="Target domain for subdomain tests")
    parser.add_argument("--rate-limit", type=float, default=3.0)
    args = parser.parse_args()

    tester = CORSTester(args.target, domain=args.domain, rate_limit=args.rate_limit)
    tester.test_all()
    tester.print_summary()
    target_name = args.target.replace("https://", "").replace("http://", "").split("/")[0]
    tester.save_findings(target_name)


if __name__ == "__main__":
    main()
