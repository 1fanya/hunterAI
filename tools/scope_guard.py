#!/usr/bin/env python3
"""
Scope Guard — Strict scope enforcement to prevent out-of-scope requests.

EVERY request MUST pass through scope guard before execution.
Prevents wasting time/tokens and accidental out-of-scope testing.

Features:
  - Loads scope from HackerOne program rules or manual config
  - Wildcard matching (*.target.com)
  - Explicit exclusion list (blog.target.com, status.target.com)
  - Third-party detection (CDN domains, SaaS platforms)
  - Audit logging of all scope checks

Usage:
    python3 scope_guard.py --target target.com --url https://api.target.com/test
    python3 scope_guard.py --import-h1 --program uber
    python3 scope_guard.py --check https://random.com  # → BLOCKED

    # From other tools:
    from scope_guard import ScopeGuard
    guard = ScopeGuard("target.com")
    if guard.is_in_scope("https://api.target.com/users"):
        # safe to test
"""

import argparse
import json
import os
import re
import sys
from datetime import datetime, timezone
from urllib.parse import urlparse

try:
    import urllib.request
except ImportError:
    pass

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TARGETS_DIR = os.path.join(BASE_DIR, "targets")
AUDIT_DIR = os.path.join(BASE_DIR, "hunt-memory")

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

# Known third-party/SaaS domains — NEVER in scope
THIRD_PARTY_DOMAINS = {
    "google.com", "googleapis.com", "gstatic.com",
    "facebook.com", "fbcdn.net",
    "twitter.com", "twimg.com",
    "github.com", "githubusercontent.com",
    "cloudflare.com", "cloudfront.net",
    "amazonaws.com", "aws.amazon.com",
    "azure.com", "azurewebsites.net",
    "jquery.com", "jsdelivr.net", "cdnjs.cloudflare.com",
    "fonts.googleapis.com", "fonts.gstatic.com",
    "gravatar.com", "wp.com",
    "intercom.io", "intercomcdn.com",
    "zendesk.com", "zdassets.com",
    "statuspage.io", "atlassian.net",
    "sentry.io", "segment.io", "segment.com",
    "mixpanel.com", "amplitude.com",
    "stripe.com", "stripe.network",
    "recaptcha.net", "gstatic.com",
    "googletagmanager.com", "google-analytics.com",
    "hotjar.com", "clarity.ms",
}


class ScopeGuard:
    """Strict scope enforcement for bug bounty hunting."""

    def __init__(self, program_name: str = None):
        self.program_name = program_name
        self.in_scope = []      # List of domain patterns (e.g., "*.target.com")
        self.out_of_scope = []  # Explicit exclusions
        self.excluded_classes = []  # Bug classes the program won't pay for
        self.scope_file = None
        self.check_count = 0
        self.blocked_count = 0
        self.audit_log = []

        if program_name:
            self._load_scope(program_name)

    def _load_scope(self, program_name: str):
        """Load scope from targets/<program>.json or scope config."""
        # Try program-specific scope file
        scope_file = os.path.join(TARGETS_DIR, f"{program_name}_scope.json")
        if not os.path.exists(scope_file):
            scope_file = os.path.join(TARGETS_DIR, f"{program_name}.json")

        if os.path.exists(scope_file):
            try:
                with open(scope_file) as f:
                    data = json.load(f)

                self.in_scope = data.get("in_scope", data.get("scope_domains", []))
                self.out_of_scope = data.get("out_of_scope", [])
                self.excluded_classes = data.get("excluded_classes",
                    data.get("rules", {}).get("excluded_classes", []))
                self.scope_file = scope_file
                log("ok", f"Scope loaded: {len(self.in_scope)} in-scope, "
                    f"{len(self.out_of_scope)} excluded")
            except (json.JSONDecodeError, IOError) as e:
                log("err", f"Failed to load scope: {e}")

    def set_scope(self, in_scope: list, out_of_scope: list = None,
                  excluded_classes: list = None):
        """Manually set scope domains."""
        self.in_scope = in_scope
        self.out_of_scope = out_of_scope or []
        self.excluded_classes = excluded_classes or []
        log("ok", f"Scope set: {len(self.in_scope)} in-scope domains")

    def save_scope(self, program_name: str = None):
        """Save scope to disk for persistence."""
        name = program_name or self.program_name or "default"
        os.makedirs(TARGETS_DIR, exist_ok=True)

        scope_file = os.path.join(TARGETS_DIR, f"{name}_scope.json")
        data = {
            "program": name,
            "in_scope": self.in_scope,
            "out_of_scope": self.out_of_scope,
            "excluded_classes": self.excluded_classes,
            "saved_at": datetime.now(timezone.utc).isoformat(),
        }
        with open(scope_file, "w") as f:
            json.dump(data, f, indent=2)
        log("ok", f"Scope saved to {scope_file}")

    def _match_domain(self, url_domain: str, scope_pattern: str) -> bool:
        """Check if a domain matches a scope pattern.

        Supports:
          - Exact match: "api.target.com"
          - Wildcard: "*.target.com" matches any subdomain
          - Root: "target.com" matches target.com and *.target.com
        """
        url_domain = url_domain.lower().strip()
        scope_pattern = scope_pattern.lower().strip()

        # Remove protocol if present
        if "://" in scope_pattern:
            scope_pattern = urlparse(scope_pattern).netloc or scope_pattern

        # Exact match
        if url_domain == scope_pattern:
            return True

        # Wildcard *.domain.com
        if scope_pattern.startswith("*."):
            parent = scope_pattern[2:]
            return url_domain == parent or url_domain.endswith(f".{parent}")

        # Root domain match (target.com should match sub.target.com)
        if url_domain.endswith(f".{scope_pattern}"):
            return True

        return False

    def is_in_scope(self, url: str) -> bool:
        """Check if a URL is in scope. Returns True if allowed.

        This is the MAIN gate — call this before EVERY request.
        """
        self.check_count += 1

        try:
            parsed = urlparse(url)
            domain = parsed.netloc or parsed.path
            domain = domain.split(":")[0].lower()  # Remove port
        except Exception:
            self._audit("BLOCKED", url, "invalid_url")
            self.blocked_count += 1
            return False

        if not domain:
            self._audit("BLOCKED", url, "empty_domain")
            self.blocked_count += 1
            return False

        # Check 1: Third-party domains (always blocked)
        for tp in THIRD_PARTY_DOMAINS:
            if domain == tp or domain.endswith(f".{tp}"):
                self._audit("BLOCKED", url, f"third_party:{tp}")
                self.blocked_count += 1
                return False

        # Check 2: Explicit out-of-scope
        for oos in self.out_of_scope:
            if self._match_domain(domain, oos):
                self._audit("BLOCKED", url, f"out_of_scope:{oos}")
                self.blocked_count += 1
                return False

        # Check 3: Must match at least one in-scope pattern
        if not self.in_scope:
            # No scope defined — allow (but warn)
            self._audit("WARN", url, "no_scope_defined")
            return True

        for ins in self.in_scope:
            if self._match_domain(domain, ins):
                self._audit("ALLOWED", url, f"matched:{ins}")
                return True

        # Not in any in-scope pattern → blocked
        self._audit("BLOCKED", url, "not_in_scope")
        self.blocked_count += 1
        return False

    def is_vuln_class_excluded(self, vuln_class: str) -> bool:
        """Check if a vulnerability class is excluded by the program."""
        return vuln_class.lower() in [ec.lower() for ec in self.excluded_classes]

    def filter_urls(self, urls: list) -> list:
        """Filter a list of URLs, returning only in-scope ones."""
        return [u for u in urls if self.is_in_scope(u)]

    def _audit(self, result: str, url: str, reason: str):
        """Log scope check to audit trail."""
        entry = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "result": result,
            "url": url[:200],
            "reason": reason,
        }
        self.audit_log.append(entry)

        # Keep audit log bounded
        if len(self.audit_log) > 10000:
            self.audit_log = self.audit_log[-5000:]

    def save_audit_log(self):
        """Save audit log to disk."""
        os.makedirs(AUDIT_DIR, exist_ok=True)
        audit_file = os.path.join(AUDIT_DIR, "scope_audit.jsonl")
        with open(audit_file, "a") as f:
            for entry in self.audit_log:
                f.write(json.dumps(entry) + "\n")
        self.audit_log = []

    def import_from_h1(self, program_handle: str):
        """Import scope from HackerOne program page."""
        log("info", f"Importing scope from HackerOne: {program_handle}")

        h1_token = os.environ.get("H1_API_TOKEN", "")

        # Try API first
        if h1_token:
            try:
                url = f"https://api.hackerone.com/v1/hackers/programs/{program_handle}"
                req = urllib.request.Request(url)
                req.add_header("Accept", "application/json")
                req.add_header("Authorization", f"Bearer {h1_token}")

                resp = urllib.request.urlopen(req, timeout=15)
                data = json.loads(resp.read().decode())

                # Extract scope from structured_scopes
                scopes = data.get("relationships", {}).get(
                    "structured_scopes", {}).get("data", [])

                for scope in scopes:
                    attrs = scope.get("attributes", {})
                    asset = attrs.get("asset_identifier", "")
                    eligible = attrs.get("eligible_for_bounty", False)
                    asset_type = attrs.get("asset_type", "")

                    if asset_type in ("URL", "WILDCARD", "DOMAIN") and eligible:
                        self.in_scope.append(asset)
                    elif not eligible and asset:
                        self.out_of_scope.append(asset)

                log("ok", f"Imported from H1 API: {len(self.in_scope)} in-scope")
                self.save_scope(program_handle)
                return True

            except Exception as e:
                log("warn", f"H1 API failed: {e}, trying scrape...")

        # Fallback: scrape program page
        try:
            url = f"https://hackerone.com/{program_handle}"
            req = urllib.request.Request(url)
            req.add_header("User-Agent", "Mozilla/5.0")
            resp = urllib.request.urlopen(req, timeout=15)
            body = resp.read().decode("utf-8", errors="replace")

            # Extract domains from page content
            for match in re.finditer(
                r'(?:In [Ss]cope|[Ee]ligible).*?(?:domain|url|asset).*?'
                r'([a-zA-Z0-9*][\w.-]+\.[a-zA-Z]{2,})', body):
                domain = match.group(1)
                if domain not in self.in_scope:
                    self.in_scope.append(domain)

            if self.in_scope:
                log("ok", f"Scraped {len(self.in_scope)} scope domains")
                self.save_scope(program_handle)
                return True
            else:
                log("warn", "Could not extract scope — set manually")
                return False

        except Exception as e:
            log("err", f"Scope import failed: {e}")
            return False

    def print_summary(self):
        """Print scope summary."""
        print(f"\n{BOLD}Scope Summary{NC}")
        print(f"{'─' * 50}")
        print(f"  Program: {self.program_name or 'not set'}")
        print(f"  In-scope: {len(self.in_scope)} domains")
        for d in self.in_scope[:10]:
            print(f"    ✅ {d}")
        if len(self.in_scope) > 10:
            print(f"    ... and {len(self.in_scope) - 10} more")
        print(f"  Out-of-scope: {len(self.out_of_scope)} domains")
        for d in self.out_of_scope[:5]:
            print(f"    ❌ {d}")
        if self.excluded_classes:
            print(f"  Excluded vuln classes: {', '.join(self.excluded_classes)}")
        print(f"  Checks: {self.check_count} total, {self.blocked_count} blocked")
        print()


def main():
    p = argparse.ArgumentParser(description="Scope Guard — Strict Scope Enforcement")
    p.add_argument("--program", help="Program name")
    p.add_argument("--url", help="URL to check")
    p.add_argument("--check", help="Quick scope check on URL")
    p.add_argument("--import-h1", action="store_true", help="Import scope from HackerOne")
    p.add_argument("--add-scope", nargs="+", help="Add in-scope domains")
    p.add_argument("--add-exclude", nargs="+", help="Add out-of-scope domains")
    p.add_argument("--show", action="store_true", help="Show current scope")
    args = p.parse_args()

    guard = ScopeGuard(args.program)

    if args.import_h1 and args.program:
        guard.import_from_h1(args.program)
        guard.print_summary()
        return

    if args.add_scope:
        guard.in_scope.extend(args.add_scope)
        guard.save_scope()
        guard.print_summary()
        return

    if args.add_exclude:
        guard.out_of_scope.extend(args.add_exclude)
        guard.save_scope()
        return

    if args.show:
        guard.print_summary()
        return

    url = args.url or args.check
    if url:
        result = guard.is_in_scope(url)
        if result:
            log("ok", f"IN SCOPE: {url}")
        else:
            log("err", f"OUT OF SCOPE: {url}")
        sys.exit(0 if result else 1)

    guard.print_summary()


if __name__ == "__main__":
    main()
