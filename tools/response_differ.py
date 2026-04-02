#!/usr/bin/env python3
"""
Response Differ — Semantic response comparison for IDOR and auth bypass detection.

Compares HTTP responses between two users (attacker vs victim) at the field level.
Detects when User A can see User B's data — not just status code matching, but
actual data leakage in JSON, HTML, and XML responses.

Key features:
  - JSON deep diff: compares keys, values, array lengths
  - HTML diff: extracts text content and input values
  - Noise filtering: ignores timestamps, CSRF tokens, session IDs, request IDs
  - PII detection: flags emails, phone numbers, SSNs, credit cards in leaked data
  - Confidence scoring: rates likelihood that observed diff is a real IDOR

Usage:
    python3 response_differ.py --url https://api.target.com/users/123/profile \
        --attacker-token "eyJ..." --victim-token "eyJ..."

    # From other tools:
    from response_differ import ResponseDiffer
    differ = ResponseDiffer()
    result = differ.compare(url, attacker_headers, victim_headers)
    if result["idor_confirmed"]:
        print(f"IDOR: attacker sees victim data with {result['confidence']}% confidence")
"""

import argparse
import hashlib
import json
import os
import re
import sys
import time
from datetime import datetime, timezone
from urllib.parse import urlparse

try:
    import urllib.request
    import urllib.error
except ImportError:
    pass

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FINDINGS_DIR = os.path.join(BASE_DIR, "findings")

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


# Fields to ignore during comparison (dynamic/noise fields)
NOISE_FIELDS = {
    "timestamp", "ts", "created_at", "updated_at", "modified_at",
    "last_login", "last_seen", "last_active",
    "csrf", "csrf_token", "_csrf", "xsrf",
    "request_id", "req_id", "trace_id", "correlation_id",
    "session_id", "sid",
    "nonce", "state",
    "cache_key", "etag",
}

# PII patterns to detect in leaked data
PII_PATTERNS = {
    "email": re.compile(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'),
    "phone": re.compile(r'(?:\+?1[-.\s]?)?\(?[0-9]{3}\)?[-.\s]?[0-9]{3}[-.\s]?[0-9]{4}'),
    "ssn": re.compile(r'\b\d{3}-\d{2}-\d{4}\b'),
    "credit_card": re.compile(r'\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13})\b'),
    "ip_address": re.compile(r'\b(?:10|172\.(?:1[6-9]|2[0-9]|3[01])|192\.168)\.\d{1,3}\.\d{1,3}\b'),
    "api_key": re.compile(r'(?:api[_-]?key|secret|token|password)\s*[:=]\s*["\']?([a-zA-Z0-9_\-]{16,})', re.IGNORECASE),
    "uuid": re.compile(r'\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b', re.IGNORECASE),
}

# Sensitive field names (data that indicates real IDOR if leaked)
SENSITIVE_FIELDS = {
    "email", "phone", "phone_number", "mobile",
    "address", "street", "city", "zip", "zipcode", "postal",
    "ssn", "social_security",
    "password", "password_hash", "hashed_password",
    "credit_card", "card_number", "cvv", "expiry",
    "bank_account", "routing_number", "iban",
    "date_of_birth", "dob", "birthday",
    "full_name", "first_name", "last_name", "name",
    "balance", "wallet", "credits", "points",
    "private_key", "secret_key", "api_key", "access_token",
    "invoice", "order", "transaction",
}


def http_request(url, headers=None, method="GET", timeout=15):
    """Make HTTP request and return response details."""
    try:
        req = urllib.request.Request(url, method=method)
        req.add_header("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0")
        req.add_header("Accept", "application/json, text/html, */*")

        if headers:
            for k, v in headers.items():
                req.add_header(k, v)

        start = time.time()
        resp = urllib.request.urlopen(req, timeout=timeout)
        elapsed = time.time() - start

        body = resp.read().decode("utf-8", errors="replace")
        resp_headers = dict(resp.getheaders())

        return {
            "status": resp.getcode(),
            "headers": resp_headers,
            "body": body,
            "size": len(body),
            "time_ms": int(elapsed * 1000),
            "content_type": resp_headers.get("Content-Type", ""),
        }
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", errors="replace") if e.fp else ""
        return {
            "status": e.code,
            "headers": dict(e.headers),
            "body": body,
            "size": len(body),
            "time_ms": 0,
            "content_type": e.headers.get("Content-Type", ""),
        }
    except Exception as e:
        return {
            "status": 0,
            "headers": {},
            "body": str(e),
            "size": 0,
            "time_ms": 0,
            "content_type": "",
            "error": str(e),
        }


class ResponseDiffer:
    """Semantic HTTP response comparison for IDOR detection."""

    def __init__(self, rate_limit=2.0):
        self.rate_limit = rate_limit
        self.findings = []

    def _sleep(self):
        time.sleep(1.0 / self.rate_limit)

    def _is_noise_field(self, field_name: str) -> bool:
        """Check if a field name is a known noise field."""
        return field_name.lower() in NOISE_FIELDS

    def _is_sensitive_field(self, field_name: str) -> bool:
        """Check if a field contains sensitive data."""
        return field_name.lower() in SENSITIVE_FIELDS

    def _detect_pii(self, text: str) -> list:
        """Detect PII patterns in text."""
        found = []
        for pii_type, pattern in PII_PATTERNS.items():
            matches = pattern.findall(text)
            if matches:
                found.append({
                    "type": pii_type,
                    "count": len(matches),
                    "sample": matches[0][:20] + "..." if len(matches[0]) > 20 else matches[0],
                })
        return found

    def _flatten_json(self, obj, prefix="") -> dict:
        """Flatten nested JSON into dot-notation key-value pairs."""
        flat = {}
        if isinstance(obj, dict):
            for k, v in obj.items():
                new_key = f"{prefix}.{k}" if prefix else k
                if isinstance(v, (dict, list)):
                    flat.update(self._flatten_json(v, new_key))
                else:
                    flat[new_key] = v
        elif isinstance(obj, list):
            flat[f"{prefix}.__len__"] = len(obj)
            for i, item in enumerate(obj[:5]):  # Only first 5 items
                flat.update(self._flatten_json(item, f"{prefix}[{i}]"))
        else:
            flat[prefix] = obj
        return flat

    def _diff_json(self, victim_body: str, attacker_body: str) -> dict:
        """Deep diff two JSON responses.

        Returns dict with:
            - shared_keys: keys present in both
            - victim_only_keys: keys only in victim response
            - attacker_only_keys: keys only in attacker response
            - value_matches: keys where attacker sees victim's values
            - sensitive_leaked: sensitive fields with victim values visible to attacker
        """
        try:
            victim_json = json.loads(victim_body)
            attacker_json = json.loads(attacker_body)
        except json.JSONDecodeError:
            return {"error": "not_json"}

        victim_flat = self._flatten_json(victim_json)
        attacker_flat = self._flatten_json(attacker_json)

        victim_keys = set(victim_flat.keys())
        attacker_keys = set(attacker_flat.keys())

        # Filter out noise fields
        def filter_noise(keys):
            return {k for k in keys if not any(
                self._is_noise_field(part) for part in k.split(".")
            )}

        victim_keys_clean = filter_noise(victim_keys)
        attacker_keys_clean = filter_noise(attacker_keys)

        shared = victim_keys_clean & attacker_keys_clean
        victim_only = victim_keys_clean - attacker_keys_clean
        attacker_only = attacker_keys_clean - victim_keys_clean

        # Check for value matches (attacker sees victim's data)
        value_matches = []
        sensitive_leaked = []

        for key in shared:
            v_val = victim_flat.get(key)
            a_val = attacker_flat.get(key)
            if v_val is not None and v_val == a_val:
                is_sensitive = any(
                    self._is_sensitive_field(part) for part in key.split(".")
                )
                match_info = {
                    "field": key,
                    "value": str(v_val)[:100],
                    "sensitive": is_sensitive,
                }
                value_matches.append(match_info)
                if is_sensitive:
                    sensitive_leaked.append(match_info)

        return {
            "format": "json",
            "shared_keys": len(shared),
            "victim_only_keys": len(victim_only),
            "attacker_only_keys": len(attacker_only),
            "value_matches": len(value_matches),
            "sensitive_leaked": sensitive_leaked,
            "sample_matches": value_matches[:10],
            "structure_match": victim_keys_clean == attacker_keys_clean,
        }

    def _diff_html(self, victim_body: str, attacker_body: str) -> dict:
        """Compare HTML responses by extracting meaningful text content."""
        def extract_text_values(html):
            """Extract visible text and input values from HTML."""
            values = set()
            # Input field values
            for match in re.finditer(r'value="([^"]+)"', html, re.IGNORECASE):
                val = match.group(1).strip()
                if len(val) > 2:
                    values.add(val)
            # Text between tags (simplified)
            for match in re.finditer(r'>([^<]{3,100})<', html):
                val = match.group(1).strip()
                if val and not val.startswith('{') and not val.startswith('//'):
                    values.add(val)
            return values

        victim_values = extract_text_values(victim_body)
        attacker_values = extract_text_values(attacker_body)

        # Victim-specific values that appear in attacker's response = data leak
        leaked = victim_values & attacker_values
        victim_unique = victim_values - attacker_values

        # Check for PII in leaked content
        leaked_pii = []
        for val in leaked:
            pii = self._detect_pii(val)
            if pii:
                leaked_pii.extend(pii)

        return {
            "format": "html",
            "victim_values": len(victim_values),
            "attacker_values": len(attacker_values),
            "shared_values": len(leaked),
            "victim_unique": len(victim_unique),
            "leaked_pii": leaked_pii,
            "sample_shared": list(leaked)[:5],
        }

    def compare(self, url: str, attacker_headers: dict, victim_headers: dict,
                method: str = "GET") -> dict:
        """Compare responses between attacker and victim on the same URL.

        Steps:
        1. Request as victim (baseline — what victim normally sees)
        2. Request as attacker (IDOR test — does attacker see victim's data?)
        3. Diff the two responses at field level
        4. Score confidence of IDOR

        Returns:
            dict with idor_confirmed, confidence, diff details, PII
        """
        log("info", f"Comparing: {method} {url}")

        # Step 1: Request as victim (baseline)
        resp_victim = http_request(url, headers=victim_headers, method=method)
        self._sleep()

        # Step 2: Request as attacker
        resp_attacker = http_request(url, headers=attacker_headers, method=method)
        self._sleep()

        result = {
            "url": url,
            "method": method,
            "victim_status": resp_victim["status"],
            "attacker_status": resp_attacker["status"],
            "victim_size": resp_victim["size"],
            "attacker_size": resp_attacker["size"],
            "idor_confirmed": False,
            "confidence": 0,
            "diff": {},
            "pii_leaked": [],
            "severity": "none",
            "ts": datetime.now(timezone.utc).isoformat(),
        }

        # Quick checks
        if resp_attacker["status"] in (401, 403):
            log("info", f"  Access denied ({resp_attacker['status']}) → No IDOR")
            return result

        if resp_victim["status"] in (401, 403, 404, 0):
            log("warn", f"  Victim request failed ({resp_victim['status']}) → Cannot compare")
            return result

        if resp_attacker["status"] != 200:
            log("info", f"  Attacker got {resp_attacker['status']} → Unclear")
            return result

        # Body comparison
        content_type = resp_attacker.get("content_type", "")
        if "json" in content_type or resp_attacker["body"].strip().startswith("{"):
            diff = self._diff_json(resp_victim["body"], resp_attacker["body"])
        elif "html" in content_type:
            diff = self._diff_html(resp_victim["body"], resp_attacker["body"])
        else:
            # Raw text comparison
            body_match = resp_victim["body"].strip() == resp_attacker["body"].strip()
            diff = {
                "format": "text",
                "exact_match": body_match,
                "size_diff": abs(resp_victim["size"] - resp_attacker["size"]),
            }

        result["diff"] = diff

        # PII detection on attacker's response
        pii = self._detect_pii(resp_attacker["body"])
        result["pii_leaked"] = pii

        # Confidence scoring
        confidence = 0

        if diff.get("format") == "json":
            if diff.get("sensitive_leaked"):
                confidence += 40
                for sl in diff["sensitive_leaked"]:
                    confidence += 10  # +10 per sensitive field
            if diff.get("structure_match"):
                confidence += 15
            if diff.get("value_matches", 0) > 3:
                confidence += 10
        elif diff.get("format") == "html":
            if diff.get("leaked_pii"):
                confidence += 50
            if diff.get("shared_values", 0) > 5:
                confidence += 20
        elif diff.get("format") == "text":
            if diff.get("exact_match"):
                confidence += 30

        # PII boosts confidence significantly
        if pii:
            confidence += 20
            for p in pii:
                if p["type"] in ("email", "ssn", "credit_card"):
                    confidence += 15

        # Size similarity (within 20%) suggests same data structure
        if resp_victim["size"] > 0:
            size_ratio = resp_attacker["size"] / resp_victim["size"]
            if 0.8 <= size_ratio <= 1.2:
                confidence += 10

        confidence = min(confidence, 100)
        result["confidence"] = confidence

        # Determine IDOR
        if confidence >= 60:
            result["idor_confirmed"] = True
            if confidence >= 80 or any(p["type"] in ("ssn", "credit_card") for p in pii):
                result["severity"] = "high"
            else:
                result["severity"] = "medium"
            log("ok", f"  IDOR CONFIRMED ({confidence}% confidence) — Severity: {result['severity']}")
        elif confidence >= 30:
            log("warn", f"  Partial signal ({confidence}% confidence) — needs manual review")
            result["severity"] = "low"
        else:
            log("info", f"  No IDOR ({confidence}% confidence)")

        if result["idor_confirmed"] or confidence >= 30:
            self.findings.append(result)

        return result

    def compare_multiple(self, urls: list, attacker_headers: dict,
                         victim_headers: dict, method: str = "GET") -> list:
        """Compare multiple URLs for IDOR."""
        results = []
        for url in urls:
            result = self.compare(url, attacker_headers, victim_headers, method)
            results.append(result)
        return results

    def save_findings(self, target_name: str):
        """Save IDOR findings to disk."""
        if not self.findings:
            return

        out_dir = os.path.join(FINDINGS_DIR, target_name)
        os.makedirs(out_dir, exist_ok=True)

        out_file = os.path.join(out_dir, "idor_diff_results.json")
        with open(out_file, "w") as f:
            json.dump(self.findings, f, indent=2)
        log("ok", f"Saved {len(self.findings)} IDOR findings to {out_file}")

    def print_summary(self):
        """Print summary of findings."""
        confirmed = [f for f in self.findings if f["idor_confirmed"]]
        partial = [f for f in self.findings if not f["idor_confirmed"]]

        print(f"\n{BOLD}Response Differ Summary{NC}")
        print(f"{'─' * 50}")
        print(f"  Confirmed IDOR: {len(confirmed)}")
        print(f"  Partial signals: {len(partial)}")

        for f in confirmed:
            pii_str = ", ".join(p["type"] for p in f.get("pii_leaked", []))
            print(f"  🔴 [{f['severity'].upper()}] {f['url']} — {f['confidence']}% confidence")
            if pii_str:
                print(f"      PII: {pii_str}")
        print()


def main():
    parser = argparse.ArgumentParser(description="Response Differ — IDOR detection via semantic response comparison")
    parser.add_argument("--url", required=True, help="URL to test for IDOR")
    parser.add_argument("--attacker-token", required=True, help="Attacker's auth token")
    parser.add_argument("--victim-token", required=True, help="Victim's auth token")
    parser.add_argument("--target", help="Target name for saving findings")
    parser.add_argument("--method", default="GET", help="HTTP method")
    parser.add_argument("--rate-limit", type=float, default=2.0, help="Requests per second")
    args = parser.parse_args()

    differ = ResponseDiffer(rate_limit=args.rate_limit)

    attacker_headers = {"Authorization": f"Bearer {args.attacker_token}"}
    victim_headers = {"Authorization": f"Bearer {args.victim_token}"}

    result = differ.compare(args.url, attacker_headers, victim_headers, method=args.method)

    print(json.dumps(result, indent=2, default=str))

    if args.target:
        differ.save_findings(args.target)


if __name__ == "__main__":
    main()
