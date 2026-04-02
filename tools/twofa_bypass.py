#!/usr/bin/env python3
"""
twofa_bypass.py — 2FA/MFA Bypass Testing

Tests common 2FA bypass techniques:
1. Response manipulation (change "success":false → true)
2. Status code bypass (change 403 → 200)
3. Direct endpoint access (skip 2FA page entirely)
4. Brute force OTP (4-6 digit codes)
5. Backup code testing
6. Rate limit testing on OTP endpoint

Usage:
    from twofa_bypass import TwoFABypass
    tester = TwoFABypass()
    results = tester.test_all("https://target.com", headers)
"""
import json
import itertools
import os
import time
from pathlib import Path
from urllib.parse import urlparse, urljoin

try:
    import requests
except ImportError:
    requests = None


class TwoFABypass:
    """Test 2FA/MFA bypass techniques."""

    def __init__(self):
        self.findings = []
        self.session = requests.Session() if requests else None
        if self.session:
            self.session.verify = False
            import urllib3
            urllib3.disable_warnings()

    def find_2fa_endpoints(self, base_url: str,
                           headers: dict = None) -> list[str]:
        """Find 2FA verification endpoints."""
        headers = headers or {}
        endpoints = []

        common_paths = [
            "/2fa", "/2fa/verify", "/mfa", "/mfa/verify",
            "/otp", "/otp/verify", "/verify-otp",
            "/auth/2fa", "/auth/mfa", "/auth/verify",
            "/api/2fa/verify", "/api/auth/2fa",
            "/login/2fa", "/signin/2fa",
            "/account/2fa", "/settings/2fa",
            "/challenge", "/auth/challenge",
        ]

        for path in common_paths:
            url = base_url.rstrip("/") + path
            try:
                resp = self.session.get(url, headers=headers, timeout=5,
                                       allow_redirects=False)
                if resp.status_code in (200, 302, 401, 403):
                    endpoints.append(url)
            except Exception:
                continue

        return endpoints

    def test_direct_access(self, base_url: str,
                           headers: dict = None) -> dict:
        """Test if protected pages are accessible without 2FA."""
        headers = headers or {}
        result = {"type": "DIRECT_ACCESS_BYPASS", "vulnerable": False,
                  "bypassed": []}

        # Pages that should require 2FA
        protected_paths = [
            "/dashboard", "/home", "/account",
            "/api/me", "/api/user", "/api/profile",
            "/settings", "/admin",
        ]

        for path in protected_paths:
            url = base_url.rstrip("/") + path
            try:
                resp = self.session.get(url, headers=headers, timeout=8)
                if resp.status_code == 200 and len(resp.text) > 200:
                    result["bypassed"].append({
                        "url": url,
                        "status": resp.status_code,
                        "length": len(resp.text),
                    })
            except Exception:
                continue

        if result["bypassed"]:
            result["vulnerable"] = True
            result["severity"] = "CRITICAL"
            self.findings.append(result)

        return result

    def test_response_manipulation(self, verify_url: str,
                                   headers: dict = None) -> dict:
        """Test if changing response body bypasses 2FA."""
        headers = headers or {}
        result = {"type": "RESPONSE_MANIPULATION", "vulnerable": False,
                  "tests": []}

        # Send wrong OTP and analyze response
        test_codes = ["000000", "123456", "111111"]

        for code in test_codes:
            for field in ["code", "otp", "token", "verify_code", "mfa_code"]:
                try:
                    # Try JSON
                    resp = self.session.post(
                        verify_url,
                        json={field: code},
                        headers={**headers,
                                "Content-Type": "application/json"},
                        timeout=8)

                    test = {
                        "code": code, "field": field,
                        "status": resp.status_code,
                        "length": len(resp.text),
                    }

                    # Analyze response structure
                    try:
                        body = resp.json()
                        test["response_keys"] = list(body.keys())[:10]

                        # If response has boolean success/verified field
                        for key in ("success", "verified", "valid",
                                   "authenticated", "passed"):
                            if key in body:
                                test["manipulable_field"] = key
                                test["current_value"] = body[key]
                    except Exception:
                        pass

                    result["tests"].append(test)
                    break  # Found working field name

                except Exception:
                    continue

            if result["tests"]:
                break

        return result

    def test_rate_limit(self, verify_url: str,
                        headers: dict = None) -> dict:
        """Test if OTP endpoint has rate limiting."""
        headers = headers or {}
        result = {"type": "RATE_LIMIT", "vulnerable": False,
                  "requests_before_block": 0}

        # Send 20 rapid requests with wrong OTPs
        for i in range(20):
            code = f"{i:06d}"
            try:
                resp = self.session.post(
                    verify_url,
                    json={"code": code},
                    headers={**headers,
                            "Content-Type": "application/json"},
                    timeout=5)

                result["requests_before_block"] += 1

                if resp.status_code == 429:
                    break  # Rate limited
                if resp.status_code == 403:
                    break  # Blocked

            except Exception:
                break

        if result["requests_before_block"] >= 20:
            result["vulnerable"] = True
            result["severity"] = "HIGH"
            result["note"] = (
                "No rate limiting on 2FA endpoint — "
                "6-digit OTP brutable in ~1M requests")
            self.findings.append(result)

        return result

    def test_code_reuse(self, verify_url: str, valid_code: str = "",
                        headers: dict = None) -> dict:
        """Test if OTP codes can be reused."""
        headers = headers or {}
        result = {"type": "CODE_REUSE", "vulnerable": False}

        if not valid_code:
            return result

        # Try submitting the same code twice
        for i in range(3):
            try:
                resp = self.session.post(
                    verify_url,
                    json={"code": valid_code},
                    headers={**headers,
                            "Content-Type": "application/json"},
                    timeout=8)

                if resp.status_code == 200 and i > 0:
                    result["vulnerable"] = True
                    result["severity"] = "HIGH"
                    result["reuse_count"] = i + 1
                    self.findings.append(result)
                    break

            except Exception:
                break

        return result

    def test_backup_codes(self, verify_url: str,
                          headers: dict = None) -> dict:
        """Test weak backup codes."""
        headers = headers or {}
        result = {"type": "BACKUP_CODES", "tests": []}

        weak_codes = [
            "00000000", "12345678", "11111111",
            "backup", "recovery", "000000",
        ]

        for code in weak_codes:
            for field in ["backup_code", "recovery_code", "code"]:
                try:
                    resp = self.session.post(
                        verify_url,
                        json={field: code},
                        headers={**headers,
                                "Content-Type": "application/json"},
                        timeout=5)

                    if resp.status_code == 200:
                        result["tests"].append({
                            "code": code, "field": field,
                            "accepted": True,
                        })
                except Exception:
                    continue

        return result

    def test_all(self, base_url: str, headers: dict = None) -> dict:
        """Run all 2FA bypass tests."""
        headers = headers or {}
        results = {
            "base_url": base_url,
            "endpoints_found": [],
            "direct_access": {},
            "response_manipulation": {},
            "rate_limit": {},
            "backup_codes": {},
            "total_findings": 0,
        }

        # Find 2FA endpoints
        endpoints = self.find_2fa_endpoints(base_url, headers)
        results["endpoints_found"] = endpoints

        if not endpoints:
            results["note"] = "No 2FA endpoints found"
            return results

        verify_url = endpoints[0]

        results["direct_access"] = self.test_direct_access(base_url, headers)
        results["response_manipulation"] = self.test_response_manipulation(
            verify_url, headers)
        results["rate_limit"] = self.test_rate_limit(verify_url, headers)
        results["backup_codes"] = self.test_backup_codes(verify_url, headers)
        results["total_findings"] = len(self.findings)

        return results

    def save_findings(self, target: str) -> None:
        out_dir = Path(f"findings/{target}/2fa_bypass")
        out_dir.mkdir(parents=True, exist_ok=True)
        if self.findings:
            out_file = out_dir / f"2fa_{int(time.time())}.json"
            out_file.write_text(json.dumps(self.findings, indent=2, default=str))
