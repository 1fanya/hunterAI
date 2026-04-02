#!/usr/bin/env python3
"""
api_security.py — OWASP API Top 10 Security Tester

Tests: BOLA, BFLA, mass assignment, excessive data exposure, rate limiting.
Auto-discovers API structure from OpenAPI/Swagger specs.

Usage:
    python3 api_security.py --target https://api.target.com \
        --attacker-token TOKEN_A --victim-token TOKEN_B --victim-id 12345
"""
import json
import os
import re
import time
from pathlib import Path
from urllib.parse import urlparse, urljoin

try:
    import requests
except ImportError:
    requests = None

# ── Mass Assignment Fields ─────────────────────────────────────────────────────

MASS_ASSIGN_FIELDS = {
    "privilege_escalation": [
        "role", "roles", "is_admin", "isAdmin", "admin", "is_staff",
        "is_superuser", "isSuperuser", "permission", "permissions",
        "access_level", "accessLevel", "privilege", "group", "groups",
        "user_type", "userType", "account_type", "accountType",
        "is_moderator", "isModerator", "is_verified", "isVerified",
    ],
    "account_manipulation": [
        "email", "email_verified", "emailVerified", "phone_verified",
        "phoneVerified", "verified", "active", "is_active", "isActive",
        "disabled", "banned", "suspended", "locked", "status",
        "two_factor", "twoFactor", "mfa_enabled", "mfaEnabled",
    ],
    "financial": [
        "balance", "credits", "points", "coins", "tokens",
        "subscription", "plan", "tier", "premium", "pro",
        "trial_end", "trialEnd", "billing_plan", "billingPlan",
        "discount", "discount_percent", "price", "amount",
    ],
    "metadata": [
        "id", "user_id", "userId", "created_at", "createdAt",
        "updated_at", "updatedAt", "org_id", "orgId", "tenant_id",
        "tenantId", "company_id", "companyId", "owner_id", "ownerId",
    ],
}


class APISecurityTester:
    """OWASP API Top 10 vulnerability tester."""

    def __init__(self, target_base: str = ""):
        self.target_base = target_base.rstrip("/")
        self.findings = []
        self.session = requests.Session() if requests else None

    def test_bola(self, endpoints: list[str], attacker_headers: dict,
                  victim_id: str, attacker_id: str = "") -> list[dict]:
        """Test Broken Object Level Authorization (BOLA/IDOR).
        
        Systematically swap IDs across all API endpoints.
        """
        findings = []
        id_patterns = [
            (r'/(\d+)(?:/|$)', 'numeric'),
            (r'/([a-f0-9-]{36})(?:/|$)', 'uuid'),
            (r'/([a-f0-9]{24})(?:/|$)', 'mongo_objectid'),
            (r'[?&](?:id|user_id|userId|account_id)=([^&]+)', 'query_param'),
        ]

        for endpoint in endpoints:
            url = urljoin(self.target_base, endpoint) if not endpoint.startswith("http") else endpoint

            for pattern, id_type in id_patterns:
                match = re.search(pattern, url)
                if not match:
                    continue

                original_id = match.group(1)
                # Replace with victim_id
                test_url = url[:match.start(1)] + victim_id + url[match.end(1):]

                try:
                    # Request as attacker but with victim's resource ID
                    resp = self.session.get(test_url, headers=attacker_headers, timeout=10)

                    if resp.status_code == 200:
                        body = resp.text
                        # Check if response contains victim-specific data
                        victim_markers = [victim_id]
                        has_victim_data = any(m in body for m in victim_markers)

                        finding = {
                            "type": "BOLA",
                            "endpoint": endpoint,
                            "test_url": test_url,
                            "original_id": original_id,
                            "victim_id": victim_id,
                            "id_type": id_type,
                            "status": resp.status_code,
                            "body_length": len(body),
                            "has_victim_data": has_victim_data,
                            "severity": "HIGH" if has_victim_data else "MEDIUM",
                            "body_preview": body[:500],
                        }

                        # Test write operations too
                        for method in ["PUT", "PATCH", "DELETE"]:
                            try:
                                write_resp = self.session.request(
                                    method, test_url, headers=attacker_headers,
                                    json={}, timeout=8)
                                if write_resp.status_code in (200, 201, 204):
                                    finding["write_access"] = True
                                    finding["write_method"] = method
                                    finding["severity"] = "CRITICAL"
                                    break
                            except Exception:
                                continue

                        findings.append(finding)
                        self.findings.append(finding)

                except Exception:
                    continue

            time.sleep(0.3)

        return findings

    def test_bfla(self, admin_endpoints: list[str],
                  user_headers: dict) -> list[dict]:
        """Test Broken Function Level Authorization (BFLA).
        
        Access admin/privileged endpoints with regular user credentials.
        """
        findings = []

        # Common admin endpoint patterns
        admin_patterns = [
            "/admin", "/admin/", "/api/admin",
            "/api/v1/admin", "/api/v2/admin",
            "/dashboard", "/api/dashboard",
            "/api/users", "/api/v1/users",
            "/api/internal", "/api/config",
            "/api/settings", "/api/audit",
            "/api/logs", "/api/metrics",
            "/api/billing", "/api/subscriptions",
            "/manage", "/api/manage",
        ]

        test_endpoints = list(set(admin_endpoints + admin_patterns))

        for endpoint in test_endpoints:
            url = urljoin(self.target_base, endpoint) if not endpoint.startswith("http") else endpoint

            try:
                resp = self.session.get(url, headers=user_headers, timeout=8)

                if resp.status_code == 200:
                    body = resp.text
                    # Check for admin-like content
                    admin_markers = [
                        "admin", "user_list", "users", "role",
                        "configuration", "settings", "audit",
                        "billing", "subscription", "revenue",
                    ]
                    has_admin_content = any(m in body.lower() for m in admin_markers)

                    if has_admin_content or len(body) > 100:
                        finding = {
                            "type": "BFLA",
                            "endpoint": endpoint,
                            "url": url,
                            "status": resp.status_code,
                            "body_length": len(body),
                            "has_admin_content": has_admin_content,
                            "severity": "HIGH",
                            "body_preview": body[:500],
                        }
                        findings.append(finding)
                        self.findings.append(finding)

            except Exception:
                continue

            time.sleep(0.2)

        return findings

    def test_mass_assignment(self, endpoint: str, method: str = "PUT",
                             auth_headers: dict = None,
                             original_body: dict = None) -> list[dict]:
        """Test mass assignment by injecting privilege fields into update requests."""
        findings = []
        auth_headers = auth_headers or {}
        original_body = original_body or {}
        url = urljoin(self.target_base, endpoint) if not endpoint.startswith("http") else endpoint

        # Get baseline
        try:
            baseline = self.session.get(url, headers=auth_headers, timeout=8)
            baseline_data = baseline.json() if baseline.status_code == 200 else {}
        except Exception:
            baseline_data = {}

        for category, fields in MASS_ASSIGN_FIELDS.items():
            for field in fields:
                test_body = dict(original_body)

                # Set privilege values
                if field in ("role", "roles", "user_type", "userType",
                            "account_type", "accountType"):
                    test_values = ["admin", "superadmin", "root"]
                elif field in ("is_admin", "isAdmin", "admin", "is_staff",
                              "is_superuser", "isSuperuser", "is_verified",
                              "isVerified", "verified"):
                    test_values = [True, 1, "true"]
                elif field in ("balance", "credits", "points"):
                    test_values = [999999]
                elif field in ("plan", "tier", "subscription"):
                    test_values = ["enterprise", "unlimited", "premium"]
                else:
                    test_values = ["injected_value"]

                for test_val in test_values:
                    test_body[field] = test_val

                    try:
                        resp = self.session.request(
                            method, url, headers=auth_headers,
                            json=test_body, timeout=8)

                        if resp.status_code in (200, 201, 204):
                            # Check if the field was accepted
                            try:
                                resp_data = resp.json()
                            except Exception:
                                resp_data = {}

                            accepted = False
                            if field in str(resp_data):
                                accepted = True

                            # Verify by re-fetching
                            verify_resp = self.session.get(
                                url, headers=auth_headers, timeout=8)
                            try:
                                verify_data = verify_resp.json()
                            except Exception:
                                verify_data = {}

                            if str(test_val) in str(verify_data):
                                accepted = True

                            if accepted:
                                finding = {
                                    "type": "MASS_ASSIGNMENT",
                                    "endpoint": endpoint,
                                    "field": field,
                                    "value": test_val,
                                    "category": category,
                                    "status": resp.status_code,
                                    "severity": "CRITICAL" if category == "privilege_escalation" else
                                               "HIGH" if category == "financial" else "MEDIUM",
                                }
                                findings.append(finding)
                                self.findings.append(finding)
                                break  # Found for this field, move on

                    except Exception:
                        continue

                time.sleep(0.2)

        return findings

    def test_excessive_data_exposure(self, endpoint: str,
                                     auth_headers: dict = None,
                                     unauth_headers: dict = None) -> dict:
        """Compare authenticated vs unauthenticated responses for leaked PII fields."""
        auth_headers = auth_headers or {}
        unauth_headers = unauth_headers or {}
        url = urljoin(self.target_base, endpoint) if not endpoint.startswith("http") else endpoint

        pii_fields = [
            "email", "phone", "ssn", "social_security", "dob", "date_of_birth",
            "address", "credit_card", "card_number", "cvv", "password",
            "password_hash", "secret", "api_key", "apiKey", "token",
            "access_token", "refresh_token", "private_key",
        ]

        try:
            auth_resp = self.session.get(url, headers=auth_headers, timeout=8)
            auth_body = auth_resp.text.lower()

            unauth_resp = self.session.get(url, headers=unauth_headers, timeout=8)
            unauth_body = unauth_resp.text.lower()
        except Exception:
            return {"endpoint": endpoint, "error": "request_failed"}

        leaked_fields = []
        for field in pii_fields:
            if field in unauth_body:
                leaked_fields.append(field)

        result = {
            "type": "EXCESSIVE_DATA_EXPOSURE",
            "endpoint": endpoint,
            "auth_body_length": len(auth_resp.text),
            "unauth_body_length": len(unauth_resp.text),
            "leaked_pii_fields": leaked_fields,
            "severity": "HIGH" if leaked_fields else "LOW",
        }

        if leaked_fields:
            self.findings.append(result)

        return result

    def test_rate_limiting(self, endpoint: str, auth_headers: dict = None,
                           method: str = "POST", data: dict = None,
                           attempts: int = 50) -> dict:
        """Test for missing rate limiting on sensitive endpoints."""
        auth_headers = auth_headers or {}
        url = urljoin(self.target_base, endpoint) if not endpoint.startswith("http") else endpoint

        successes = 0
        rate_limited = False

        for i in range(attempts):
            try:
                if method == "GET":
                    resp = self.session.get(url, headers=auth_headers, timeout=5)
                else:
                    resp = self.session.request(method, url, headers=auth_headers,
                                               json=data or {}, timeout=5)

                if resp.status_code == 429:
                    rate_limited = True
                    break
                elif resp.status_code in (200, 201, 204, 401, 403):
                    successes += 1

            except Exception:
                continue

        result = {
            "type": "MISSING_RATE_LIMIT",
            "endpoint": endpoint,
            "method": method,
            "attempts": attempts,
            "successes": successes,
            "rate_limited": rate_limited,
            "rate_limit_at": i + 1 if rate_limited else None,
            "severity": "MEDIUM" if not rate_limited and successes > 40 else "LOW",
        }

        if not rate_limited and successes > 40:
            self.findings.append(result)

        return result

    def discover_api_spec(self, auth_headers: dict = None) -> dict:
        """Try to find OpenAPI/Swagger spec for the target."""
        auth_headers = auth_headers or {}
        spec_paths = [
            "/openapi.json", "/swagger.json", "/api-docs",
            "/api/docs", "/v1/api-docs", "/v2/api-docs",
            "/swagger/v1/swagger.json", "/api/swagger.json",
            "/docs", "/api/openapi.json", "/.well-known/openapi.json",
            "/api/v1/openapi.json", "/api/v2/openapi.json",
        ]

        for path in spec_paths:
            url = urljoin(self.target_base, path)
            try:
                resp = self.session.get(url, headers=auth_headers, timeout=5)
                if resp.status_code == 200:
                    try:
                        spec = resp.json()
                        if "paths" in spec or "openapi" in spec or "swagger" in spec:
                            return {"found": True, "url": url, "spec": spec}
                    except Exception:
                        if "swagger" in resp.text.lower() or "openapi" in resp.text.lower():
                            return {"found": True, "url": url, "raw": resp.text[:2000]}
            except Exception:
                continue

        return {"found": False}

    def save_findings(self, target: str) -> None:
        """Save API security findings to disk."""
        out_dir = Path(f"findings/{target}/api_security")
        out_dir.mkdir(parents=True, exist_ok=True)
        if self.findings:
            out_file = out_dir / f"api_security_{int(time.time())}.json"
            out_file.write_text(json.dumps(self.findings, indent=2, default=str))
