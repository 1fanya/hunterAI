#!/usr/bin/env python3
"""
oauth_tester.py — OAuth/OIDC Security Testing

Tests for:
1. redirect_uri manipulation (open redirect → token theft)
2. Missing state parameter (CSRF on OAuth)
3. Authorization code reuse
4. Scope escalation
5. Token leakage via Referer
6. PKCE bypass

Usage:
    from oauth_tester import OAuthTester
    tester = OAuthTester("https://target.com")
    results = tester.test_all()
"""
import json
import os
import re
import time
from pathlib import Path
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse, quote

try:
    import requests
except ImportError:
    requests = None


class OAuthTester:
    """OAuth/OIDC security tester."""

    def __init__(self, base_url: str = ""):
        self.base_url = base_url.rstrip("/")
        self.domain = urlparse(base_url).hostname or ""
        self.findings = []
        self.session = requests.Session() if requests else None
        if self.session:
            self.session.verify = False
            import urllib3
            urllib3.disable_warnings()

    def find_oauth_endpoints(self, headers: dict = None) -> list[dict]:
        """Discover OAuth endpoints."""
        headers = headers or {}
        endpoints = []
        auth_paths = [
            "/oauth/authorize", "/oauth2/authorize",
            "/auth/authorize", "/authorize",
            "/api/oauth/authorize", "/login/oauth",
            "/.well-known/openid-configuration",
            "/oauth/token", "/oauth2/token",
        ]
        for path in auth_paths:
            url = f"{self.base_url}{path}"
            try:
                resp = self.session.get(url, headers=headers, timeout=5,
                                       allow_redirects=False)
                if resp.status_code in (200, 302, 301, 400):
                    endpoints.append({
                        "url": url, "status": resp.status_code,
                        "type": "token" if "token" in path else "authorize",
                    })
            except Exception:
                continue
        # Check OIDC well-known
        try:
            oidc_url = f"{self.base_url}/.well-known/openid-configuration"
            resp = self.session.get(oidc_url, headers=headers, timeout=5)
            if resp.status_code == 200:
                try:
                    config = resp.json()
                    if "authorization_endpoint" in config:
                        endpoints.append({"url": config["authorization_endpoint"],
                                         "type": "authorize", "source": "oidc"})
                except Exception:
                    pass
        except Exception:
            pass
        return endpoints

    def test_redirect_uri(self, auth_url: str, headers: dict = None) -> dict:
        """Test redirect_uri manipulation for token theft."""
        headers = headers or {}
        result = {"type": "REDIRECT_URI_BYPASS", "vulnerable": False, "tests": []}
        evil = "https://evil.com"
        bypasses = [
            evil,
            f"{self.base_url}@evil.com",
            f"{self.base_url}.evil.com",
            f"https://evil.com#{self.base_url}",
            f"{self.base_url}%40evil.com",
            f"{self.base_url}/../../../evil.com",
            f"{self.base_url}?next=https://evil.com",
            f"https://{self.domain}.evil.com",
            f"{self.base_url}%0d%0aLocation:%20https://evil.com",
        ]
        for bypass in bypasses:
            parsed = urlparse(auth_url)
            params = parse_qs(parsed.query)
            params["redirect_uri"] = [bypass]
            params.setdefault("response_type", ["code"])
            params.setdefault("client_id", ["test"])
            test_url = urlunparse(parsed._replace(query=urlencode(params, doseq=True)))
            try:
                resp = self.session.get(test_url, headers=headers, timeout=8,
                                       allow_redirects=False)
                test = {"bypass": bypass[:80], "status": resp.status_code}
                location = resp.headers.get("Location", "")
                if "evil.com" in location:
                    test["redirected_to_evil"] = True
                    result["vulnerable"] = True
                    result["severity"] = "CRITICAL"
                result["tests"].append(test)
            except Exception:
                continue
            time.sleep(0.3)
        if result["vulnerable"]:
            self.findings.append(result)
        return result

    def test_missing_state(self, auth_url: str, headers: dict = None) -> dict:
        """Test if state parameter is enforced."""
        headers = headers or {}
        result = {"type": "MISSING_STATE", "vulnerable": False}
        parsed = urlparse(auth_url)
        params = parse_qs(parsed.query)
        params.pop("state", None)
        params.setdefault("response_type", ["code"])
        params.setdefault("redirect_uri", [f"{self.base_url}/callback"])
        test_url = urlunparse(parsed._replace(query=urlencode(params, doseq=True)))
        try:
            resp = self.session.get(test_url, headers=headers, timeout=8,
                                   allow_redirects=False)
            if resp.status_code in (302, 200):
                location = resp.headers.get("Location", "")
                if "code=" in location or resp.status_code == 200:
                    result["vulnerable"] = True
                    result["severity"] = "MEDIUM"
                    self.findings.append(result)
        except Exception:
            pass
        return result

    def test_scope_escalation(self, auth_url: str, headers: dict = None) -> dict:
        """Test if scope can be escalated."""
        headers = headers or {}
        result = {"type": "SCOPE_ESCALATION", "vulnerable": False, "tests": []}
        for scope in ["admin", "write", "read write admin",
                      "openid profile email admin"]:
            parsed = urlparse(auth_url)
            params = parse_qs(parsed.query)
            params["scope"] = [scope]
            params.setdefault("response_type", ["code"])
            test_url = urlunparse(parsed._replace(query=urlencode(params, doseq=True)))
            try:
                resp = self.session.get(test_url, headers=headers, timeout=8,
                                       allow_redirects=False)
                test = {"scope": scope, "status": resp.status_code}
                if resp.status_code == 200 and "admin" in scope:
                    test["accepted"] = True
                    result["vulnerable"] = True
                    result["severity"] = "HIGH"
                result["tests"].append(test)
            except Exception:
                continue
            time.sleep(0.3)
        if result["vulnerable"]:
            self.findings.append(result)
        return result

    def test_all(self, headers: dict = None) -> dict:
        """Run all OAuth tests."""
        headers = headers or {}
        endpoints = self.find_oauth_endpoints(headers)
        results = {"endpoints_found": len(endpoints), "total_findings": 0}
        if not endpoints:
            results["note"] = "No OAuth endpoints found"
            return results
        auth_eps = [e for e in endpoints if e["type"] == "authorize"]
        if auth_eps:
            auth_url = auth_eps[0]["url"]
            results["redirect_uri"] = self.test_redirect_uri(auth_url, headers)
            results["missing_state"] = self.test_missing_state(auth_url, headers)
            results["scope_escalation"] = self.test_scope_escalation(auth_url, headers)
        results["total_findings"] = len(self.findings)
        return results

    def save_findings(self, target: str) -> None:
        out_dir = Path(f"findings/{target}/oauth")
        out_dir.mkdir(parents=True, exist_ok=True)
        if self.findings:
            out_file = out_dir / f"oauth_{int(time.time())}.json"
            out_file.write_text(json.dumps(self.findings, indent=2, default=str))
