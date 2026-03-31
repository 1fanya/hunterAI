#!/usr/bin/env python3
"""
Auth Tester — Automated IDOR & Authorization Bypass Testing

The #1 highest-ROI tool in bug bounty. Tests every endpoint for:
- IDOR (swap IDs between accounts)
- Missing authentication (no auth header)
- Broken role-based access (user → admin)
- Method swap (GET → PUT/DELETE/PATCH)
- API version rollback (/v2/ → /v1/)
- Header injection (X-User-ID, X-Org-ID)

Requires two test accounts (attacker + victim) for proper IDOR testing.

Usage:
    python3 auth_tester.py --target https://api.target.com \
        --endpoints endpoints.txt \
        --attacker-token "Bearer abc123" \
        --victim-token "Bearer def456" \
        --victim-id "456"
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


def http_request(url, method="GET", headers=None, data=None, timeout=15):
    """Make HTTP request and return response details.

    Returns dict with: status, headers, body, size, time_ms
    """
    headers = headers or {}
    start = time.time()

    try:
        if data and isinstance(data, dict):
            data = json.dumps(data).encode("utf-8")
            if "Content-Type" not in headers:
                headers["Content-Type"] = "application/json"
        elif data and isinstance(data, str):
            data = data.encode("utf-8")

        req = Request(url, data=data, headers=headers, method=method)
        with urlopen(req, timeout=timeout) as resp:
            body = resp.read().decode("utf-8", errors="replace")
            elapsed = int((time.time() - start) * 1000)
            return {
                "status": resp.status,
                "headers": dict(resp.headers),
                "body": body,
                "size": len(body),
                "time_ms": elapsed,
                "url": url,
                "method": method,
                "error": None,
            }
    except HTTPError as e:
        body = ""
        try:
            body = e.read().decode("utf-8", errors="replace")
        except Exception:
            pass
        elapsed = int((time.time() - start) * 1000)
        return {
            "status": e.code,
            "headers": dict(e.headers) if e.headers else {},
            "body": body,
            "size": len(body),
            "time_ms": elapsed,
            "url": url,
            "method": method,
            "error": str(e),
        }
    except (URLError, Exception) as e:
        elapsed = int((time.time() - start) * 1000)
        return {
            "status": 0,
            "headers": {},
            "body": "",
            "size": 0,
            "time_ms": elapsed,
            "url": url,
            "method": method,
            "error": str(e),
        }


class AuthTester:
    """Systematic IDOR and authorization bypass tester."""

    def __init__(self, base_url, attacker_token, victim_token,
                 victim_id=None, rate_limit=2.0):
        self.base_url = base_url.rstrip("/")
        self.attacker_token = attacker_token
        self.victim_token = victim_token
        self.victim_id = victim_id
        self.rate_limit = rate_limit
        self.findings = []
        self.tested = []

    def _auth_header(self, token):
        """Build auth header."""
        if not token:
            return {}
        if token.startswith("Bearer "):
            return {"Authorization": token}
        return {"Authorization": f"Bearer {token}"}

    def _sleep(self):
        """Rate limit between requests."""
        if self.rate_limit > 0:
            time.sleep(1.0 / self.rate_limit)

    def _add_finding(self, finding_type, endpoint, method, severity,
                     details, request_info, response_info):
        """Record a finding."""
        finding = {
            "type": finding_type,
            "endpoint": endpoint,
            "method": method,
            "severity": severity,
            "details": details,
            "request": request_info,
            "response": {
                "status": response_info.get("status"),
                "body_preview": response_info.get("body", "")[:500],
                "size": response_info.get("size"),
                "time_ms": response_info.get("time_ms"),
            },
            "found_at": datetime.now().isoformat(),
        }
        self.findings.append(finding)
        log("vuln", f"[{severity}] {finding_type} on {method} {endpoint}")
        log("vuln", f"  → {details}")
        return finding

    # ─── Test 1: IDOR — Access other user's resources ───

    def test_idor(self, endpoint, id_param_name="id", attacker_id="1",
                  victim_id=None):
        """Test IDOR by accessing victim's resource with attacker's auth.

        Tests:
        1. Attacker accesses own resource (baseline)
        2. Attacker accesses victim's resource (IDOR test)
        3. Compare responses — if victim data returned, IDOR confirmed
        """
        victim_id = victim_id or self.victim_id
        if not victim_id:
            return None

        # Build URLs with ID substitution
        url_own = self.base_url + endpoint.replace(f"{{{id_param_name}}}", str(attacker_id))
        url_victim = self.base_url + endpoint.replace(f"{{{id_param_name}}}", str(victim_id))

        log("info", f"IDOR test: {endpoint} (attacker={attacker_id}, victim={victim_id})")

        # Step 1: Attacker accesses own resource
        resp_own = http_request(url_own, headers=self._auth_header(self.attacker_token))
        self._sleep()

        # Step 2: Attacker accesses victim's resource
        resp_victim = http_request(url_victim, headers=self._auth_header(self.attacker_token))
        self._sleep()

        self.tested.append({"endpoint": endpoint, "test": "idor", "result": "tested"})

        # Analyze results
        if resp_victim["status"] == 200 and resp_victim["size"] > 10:
            # Check if we got different data (not just our own data reflected)
            if resp_victim["body"] != resp_own["body"]:
                return self._add_finding(
                    "IDOR",
                    endpoint,
                    "GET",
                    "HIGH",
                    f"Attacker (ID={attacker_id}) can access victim's resource (ID={victim_id}). "
                    f"Response contains {resp_victim['size']} bytes of data.",
                    {"url": url_victim, "auth": "attacker_token"},
                    resp_victim,
                )
            elif resp_victim["body"] == resp_own["body"]:
                log("info", f"  → Same response for both IDs — might be own data reflected")

        elif resp_victim["status"] in (200, 201) and resp_own["status"] in (403, 401):
            return self._add_finding(
                "IDOR",
                endpoint,
                "GET",
                "HIGH",
                f"Attacker gets {resp_victim['status']} on victim's resource but {resp_own['status']} on own. "
                f"Possible authorization confusion.",
                {"url": url_victim, "auth": "attacker_token"},
                resp_victim,
            )

        return None

    # ─── Test 2: Missing authentication ───

    def test_no_auth(self, endpoint, method="GET"):
        """Test endpoint without any authentication.

        If endpoint returns data without auth, it's missing auth check.
        """
        url = self.base_url + endpoint
        log("info", f"No-auth test: {method} {endpoint}")

        # With auth (baseline)
        resp_auth = http_request(url, method=method,
                                  headers=self._auth_header(self.attacker_token))
        self._sleep()

        # Without auth
        resp_noauth = http_request(url, method=method)
        self._sleep()

        self.tested.append({"endpoint": endpoint, "test": "no_auth", "result": "tested"})

        # If unauthenticated request returns same/similar data as authenticated
        if resp_noauth["status"] in (200, 201) and resp_auth["status"] in (200, 201):
            if resp_noauth["size"] > 50:  # Not just an empty or error response
                return self._add_finding(
                    "MISSING_AUTH",
                    endpoint,
                    method,
                    "CRITICAL" if "admin" in endpoint.lower() else "HIGH",
                    f"Endpoint returns {resp_noauth['size']} bytes without authentication. "
                    f"Same data accessible without login.",
                    {"url": url, "auth": "none"},
                    resp_noauth,
                )

        # Interesting: auth returns 403 but no-auth returns 200 (reverse auth)
        if resp_noauth["status"] == 200 and resp_auth["status"] in (403, 401):
            return self._add_finding(
                "AUTH_CONFUSION",
                endpoint,
                method,
                "HIGH",
                f"Endpoint returns 200 without auth but {resp_auth['status']} with auth. "
                f"Possible reverse authorization check.",
                {"url": url, "auth": "none"},
                resp_noauth,
            )

        return None

    # ─── Test 3: Method swap ───

    def test_method_swap(self, endpoint):
        """Test if changing HTTP method bypasses auth.

        Common pattern: GET is protected but PUT/DELETE/PATCH is not.
        """
        url = self.base_url + endpoint
        methods_to_try = ["PUT", "PATCH", "DELETE", "POST", "OPTIONS"]

        log("info", f"Method swap test: {endpoint}")

        # Baseline: GET with auth
        resp_get = http_request(url, method="GET",
                                headers=self._auth_header(self.attacker_token))
        self._sleep()

        findings = []
        for method in methods_to_try:
            resp = http_request(url, method=method,
                               headers=self._auth_header(self.attacker_token),
                               data="{}" if method in ("PUT", "PATCH", "POST") else None)
            self._sleep()

            # If a destructive method returns 200/201/204 on a resource
            if resp["status"] in (200, 201, 204) and method in ("PUT", "DELETE", "PATCH"):
                finding = self._add_finding(
                    "METHOD_SWAP",
                    endpoint,
                    method,
                    "HIGH",
                    f"{method} returns {resp['status']} — may allow unauthorized modification/deletion. "
                    f"GET returns {resp_get['status']}.",
                    {"url": url, "method": method, "auth": "attacker_token"},
                    resp,
                )
                findings.append(finding)

        self.tested.append({"endpoint": endpoint, "test": "method_swap", "result": "tested"})
        return findings

    # ─── Test 4: API version rollback ───

    def test_version_rollback(self, endpoint):
        """Test if older API versions have weaker auth.

        /api/v2/users/{id} → try /api/v1/users/{id}
        """
        versions_to_try = []

        # Detect version in URL and generate alternatives
        version_match = re.search(r'/v(\d+)/', endpoint)
        if version_match:
            current_ver = int(version_match.group(1))
            for v in range(1, current_ver + 2):
                if v != current_ver:
                    alt_endpoint = re.sub(r'/v\d+/', f'/v{v}/', endpoint)
                    versions_to_try.append((f"v{v}", alt_endpoint))

        # Also try removing version entirely
        no_version = re.sub(r'/v\d+/', '/', endpoint)
        if no_version != endpoint:
            versions_to_try.append(("no-version", no_version))

        if not versions_to_try:
            return None

        log("info", f"Version rollback test: {endpoint}")

        findings = []
        for version_name, alt_endpoint in versions_to_try:
            url = self.base_url + alt_endpoint
            resp = http_request(url, headers=self._auth_header(self.attacker_token))
            self._sleep()

            if resp["status"] == 200 and resp["size"] > 50:
                finding = self._add_finding(
                    "VERSION_ROLLBACK",
                    alt_endpoint,
                    "GET",
                    "MEDIUM",
                    f"API {version_name} ({alt_endpoint}) returns {resp['status']} with "
                    f"{resp['size']} bytes. Check if auth is weaker on older version.",
                    {"url": url, "version": version_name},
                    resp,
                )
                findings.append(finding)

        self.tested.append({"endpoint": endpoint, "test": "version_rollback", "result": "tested"})
        return findings

    # ─── Test 5: Role escalation via header injection ───

    def test_header_injection(self, endpoint, method="GET"):
        """Test if injecting role/user headers bypasses auth.

        Tests: X-User-ID, X-Org-ID, X-Role, X-Forwarded-For (127.0.0.1 for internal bypass)
        """
        url = self.base_url + endpoint
        log("info", f"Header injection test: {endpoint}")

        injection_headers = [
            ("X-User-ID", "1"),
            ("X-Org-ID", "1"),
            ("X-Role", "admin"),
            ("X-Admin", "true"),
            ("X-Forwarded-For", "127.0.0.1"),
            ("X-Original-URL", "/admin"),
            ("X-Rewrite-URL", "/admin"),
        ]

        # Baseline without injection
        resp_base = http_request(url, method=method)
        self._sleep()

        findings = []
        for header_name, header_value in injection_headers:
            headers = {header_name: header_value}
            resp = http_request(url, method=method, headers=headers)
            self._sleep()

            # If injection changes the response significantly
            if (resp["status"] in (200, 201) and resp_base["status"] in (401, 403)):
                finding = self._add_finding(
                    "HEADER_INJECTION",
                    endpoint,
                    method,
                    "CRITICAL",
                    f"Header '{header_name}: {header_value}' bypasses auth. "
                    f"Without header: {resp_base['status']}, with header: {resp['status']}.",
                    {"url": url, "injected_header": f"{header_name}: {header_value}"},
                    resp,
                )
                findings.append(finding)

            elif (resp["status"] == 200 and resp_base["status"] == 200
                  and resp["size"] > resp_base["size"] * 1.5
                  and resp["size"] > 100):
                finding = self._add_finding(
                    "HEADER_INJECTION",
                    endpoint,
                    method,
                    "MEDIUM",
                    f"Header '{header_name}: {header_value}' returns significantly more data. "
                    f"Base: {resp_base['size']}B, with header: {resp['size']}B.",
                    {"url": url, "injected_header": f"{header_name}: {header_value}"},
                    resp,
                )
                findings.append(finding)

        self.tested.append({"endpoint": endpoint, "test": "header_injection", "result": "tested"})
        return findings

    # ─── Test 6: Privilege escalation via parameter pollution ───

    def test_privilege_escalation(self, endpoint, method="POST"):
        """Test if adding role/admin parameters escalates privileges.

        Sends requests with extra params: role=admin, is_admin=true, etc.
        """
        url = self.base_url + endpoint
        log("info", f"Privilege escalation test: {endpoint}")

        payloads = [
            {"role": "admin"},
            {"is_admin": True},
            {"admin": True},
            {"user_type": "admin"},
            {"privilege": "superadmin"},
            {"group": "administrators"},
            {"permissions": ["admin", "write", "delete"]},
        ]

        findings = []
        for payload in payloads:
            headers = self._auth_header(self.attacker_token)
            headers["Content-Type"] = "application/json"
            resp = http_request(url, method=method, headers=headers,
                               data=json.dumps(payload))
            self._sleep()

            if resp["status"] in (200, 201) and resp["size"] > 50:
                # Check if response indicates privilege change
                body_lower = resp["body"].lower()
                if any(w in body_lower for w in ["admin", "superadmin", "elevated",
                                                   "privilege", "role"]):
                    finding = self._add_finding(
                        "PRIVILEGE_ESCALATION",
                        endpoint,
                        method,
                        "CRITICAL",
                        f"Mass assignment: sending {json.dumps(payload)} returns admin-related "
                        f"data. Check if role was actually changed.",
                        {"url": url, "payload": payload},
                        resp,
                    )
                    findings.append(finding)

        self.tested.append({"endpoint": endpoint, "test": "priv_esc", "result": "tested"})
        return findings

    # ─── Master test runner ───

    def test_endpoint(self, endpoint, run_all=True):
        """Run all auth tests on an endpoint."""
        all_findings = []

        # Test 1: Missing auth
        f = self.test_no_auth(endpoint)
        if f:
            all_findings.append(f)

        # Test 2: IDOR (if endpoint has ID parameter pattern)
        if re.search(r'/\d+|/\{.*\}|/[a-f0-9-]{36}', endpoint):
            f = self.test_idor(endpoint)
            if f:
                all_findings.append(f)

        if not run_all:
            return all_findings

        # Test 3: Method swap
        fs = self.test_method_swap(endpoint)
        if fs:
            all_findings.extend(fs)

        # Test 4: Version rollback
        if re.search(r'/v\d+/', endpoint):
            fs = self.test_version_rollback(endpoint)
            if fs:
                all_findings.extend(fs)

        # Test 5: Header injection
        fs = self.test_header_injection(endpoint)
        if fs:
            all_findings.extend(fs)

        # Test 6: Privilege escalation (only on POST/PUT endpoints)
        if "user" in endpoint.lower() or "profile" in endpoint.lower() or "account" in endpoint.lower():
            fs = self.test_privilege_escalation(endpoint)
            if fs:
                all_findings.extend(fs)

        return all_findings

    def test_all_endpoints(self, endpoints):
        """Test a list of endpoints."""
        all_findings = []
        total = len(endpoints)

        for i, endpoint in enumerate(endpoints):
            log("info", f"\n{'='*60}")
            log("info", f"[{i+1}/{total}] Testing: {endpoint}")
            log("info", f"{'='*60}")

            findings = self.test_endpoint(endpoint)
            all_findings.extend(findings)

            if findings:
                log("vuln", f"Found {len(findings)} issue(s) on {endpoint}")

        return all_findings

    def save_findings(self, target_name):
        """Save findings to findings directory."""
        if not self.findings:
            log("info", "No findings to save")
            return None

        output_dir = os.path.join(FINDINGS_DIR, target_name)
        os.makedirs(output_dir, exist_ok=True)

        filepath = os.path.join(output_dir, "auth_findings.json")
        with open(filepath, "w") as f:
            json.dump({
                "target": target_name,
                "scan_type": "auth_tester",
                "total_findings": len(self.findings),
                "total_tested": len(self.tested),
                "findings": self.findings,
                "tested_endpoints": self.tested,
                "scanned_at": datetime.now().isoformat(),
            }, f, indent=2)

        log("ok", f"Saved {len(self.findings)} findings to {filepath}")
        return filepath

    def print_summary(self):
        """Print scan summary."""
        print(f"\n{BOLD}{'='*60}{NC}")
        print(f"{BOLD}  Auth Test Summary{NC}")
        print(f"{BOLD}{'='*60}{NC}\n")

        print(f"  Endpoints tested: {len(self.tested)}")
        print(f"  Total findings:   {len(self.findings)}")

        # Group by severity
        by_severity = {}
        for f in self.findings:
            sev = f["severity"]
            by_severity.setdefault(sev, []).append(f)

        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
            if sev in by_severity:
                color = RED if sev in ("CRITICAL", "HIGH") else YELLOW
                print(f"\n  {color}{sev} ({len(by_severity[sev])}):{NC}")
                for finding in by_severity[sev]:
                    print(f"    • [{finding['type']}] {finding['method']} {finding['endpoint']}")
                    print(f"      {finding['details'][:100]}")

        print(f"\n{'='*60}\n")


def main():
    parser = argparse.ArgumentParser(
        description="IDOR & Authorization Bypass Tester",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--target", required=True, help="Base URL (e.g., https://api.target.com)")
    parser.add_argument("--endpoints", required=True,
                        help="File with endpoints (one per line) or comma-separated list")
    parser.add_argument("--attacker-token", required=True, help="Auth token for attacker account")
    parser.add_argument("--victim-token", default="", help="Auth token for victim account")
    parser.add_argument("--victim-id", default="", help="Victim user ID for IDOR tests")
    parser.add_argument("--rate-limit", type=float, default=2.0,
                        help="Requests per second (default: 2)")
    parser.add_argument("--quick", action="store_true", help="Quick mode (skip slow tests)")
    args = parser.parse_args()

    # Load endpoints
    if os.path.isfile(args.endpoints):
        with open(args.endpoints) as f:
            endpoints = [line.strip() for line in f if line.strip() and not line.startswith("#")]
    else:
        endpoints = [e.strip() for e in args.endpoints.split(",")]

    log("info", f"Loaded {len(endpoints)} endpoints to test")

    # Create tester
    tester = AuthTester(
        base_url=args.target,
        attacker_token=args.attacker_token,
        victim_token=args.victim_token,
        victim_id=args.victim_id,
        rate_limit=args.rate_limit,
    )

    # Run tests
    findings = tester.test_all_endpoints(endpoints)

    # Save and print results
    target_name = args.target.replace("https://", "").replace("http://", "").split("/")[0]
    tester.save_findings(target_name)
    tester.print_summary()

    return len(findings)


if __name__ == "__main__":
    sys.exit(0 if main() else 1)
