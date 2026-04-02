#!/usr/bin/env python3
"""
safe_http.py — Scope-enforced, rate-limited HTTP client with circuit breaker.

All tools should use this instead of raw requests.Session() to ensure:
1. Every request is scope-checked before firing
2. Rate limiting protects against 429 bans
3. Circuit breaker halts on repeated failures
4. Request/response logging for evidence

Usage:
    from safe_http import SafeHTTP
    http = SafeHTTP(domain="target.com", scope_domains=["*.target.com"])
    resp = http.get("https://api.target.com/users/1")
"""
import os
import json
import time
import hashlib
import logging
from collections import defaultdict
from pathlib import Path
from urllib.parse import urlparse
from typing import Optional

try:
    import requests
    from requests.adapters import HTTPAdapter
    from urllib3.util.retry import Retry
except ImportError:
    requests = None


class CircuitBreaker:
    """
    Halt requests when target is consistently rejecting.
    States: CLOSED (normal) → OPEN (halted) → HALF_OPEN (testing)
    """
    CLOSED = "CLOSED"
    OPEN = "OPEN"
    HALF_OPEN = "HALF_OPEN"

    def __init__(self, failure_threshold: int = 10,
                 recovery_timeout: int = 60):
        self.state = self.CLOSED
        self.failure_count = 0
        self.failure_threshold = failure_threshold
        self.recovery_timeout = recovery_timeout
        self.last_failure_time = 0
        self.stats = {"total_blocked": 0, "recoveries": 0}

    def record_success(self):
        if self.state == self.HALF_OPEN:
            self.state = self.CLOSED
            self.stats["recoveries"] += 1
        self.failure_count = 0

    def record_failure(self, status_code: int = 0):
        self.failure_count += 1
        self.last_failure_time = time.time()
        if self.failure_count >= self.failure_threshold:
            self.state = self.OPEN

    def can_proceed(self) -> bool:
        if self.state == self.CLOSED:
            return True
        if self.state == self.OPEN:
            # Check if recovery timeout has passed
            if time.time() - self.last_failure_time > self.recovery_timeout:
                self.state = self.HALF_OPEN
                return True
            self.stats["total_blocked"] += 1
            return False
        # HALF_OPEN: allow one test request
        return True


class RateLimiter:
    """Token bucket rate limiter — prevents 429 bans."""

    def __init__(self, requests_per_second: float = 5.0,
                 burst: int = 10):
        self.rate = requests_per_second
        self.burst = burst
        self.tokens = burst
        self.last_refill = time.time()
        self._per_host_delay = defaultdict(float)

    def wait(self, host: str = ""):
        """Block until a token is available."""
        # Refill tokens
        now = time.time()
        elapsed = now - self.last_refill
        self.tokens = min(self.burst, self.tokens + elapsed * self.rate)
        self.last_refill = now

        if self.tokens < 1:
            sleep_time = (1 - self.tokens) / self.rate
            time.sleep(sleep_time)
            self.tokens = 0
        else:
            self.tokens -= 1

        # Per-host delay (adaptive after 429s)
        delay = self._per_host_delay.get(host, 0)
        if delay > 0:
            time.sleep(delay)

    def back_off(self, host: str, multiplier: float = 2.0):
        """Increase delay for a host (after 429)."""
        current = self._per_host_delay.get(host, 0.5)
        self._per_host_delay[host] = min(current * multiplier, 30.0)

    def reset(self, host: str):
        """Reset delay for a host."""
        self._per_host_delay[host] = 0


class DedupFilter:
    """
    Deduplicate findings so the same vuln isn't reported 10 times.
    Uses (url_path, vuln_type, param) as the dedup key.
    """

    def __init__(self):
        self.seen = set()
        self.findings = []

    def is_duplicate(self, finding: dict) -> bool:
        """Check if finding is a duplicate."""
        url = finding.get("url", "")
        parsed = urlparse(url)
        # Normalize: strip IDs from path (/users/123 → /users/{id})
        import re
        path = re.sub(r'/\d+', '/{id}', parsed.path)
        path = re.sub(r'=[^&]+', '={val}', parsed.query)

        key = (
            parsed.hostname or "",
            path,
            finding.get("vuln_type", finding.get("type", "")),
            finding.get("param", ""),
        )
        key_hash = hashlib.md5(str(key).encode()).hexdigest()

        if key_hash in self.seen:
            return True

        self.seen.add(key_hash)
        return False

    def add(self, finding: dict) -> bool:
        """Add finding if not a duplicate. Returns True if added."""
        if self.is_duplicate(finding):
            return False
        self.findings.append(finding)
        return True

    def get_unique(self, min_severity: str = "MEDIUM") -> list[dict]:
        """Get unique findings at or above severity threshold."""
        severity_order = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}
        threshold = severity_order.get(min_severity, 0)
        return [
            f for f in self.findings
            if severity_order.get(f.get("severity", "LOW"), 0) >= threshold
        ]

    @property
    def stats(self) -> dict:
        return {
            "total_unique": len(self.findings),
            "total_seen": len(self.seen),
            "duplicates_filtered": len(self.seen) - len(self.findings),
        }


class SafeHTTP:
    """Scope-enforced, rate-limited HTTP client with circuit breaker."""

    def __init__(self, domain: str, scope_domains: list[str] = None,
                 rps: float = 5.0, auth_headers: dict = None):
        self.domain = domain
        self.scope_domains = scope_domains or [f"*.{domain}", domain]
        self.auth_headers = auth_headers or {}
        self.rate_limiter = RateLimiter(requests_per_second=rps)
        self.circuit_breaker = CircuitBreaker()
        self.dedup = DedupFilter()
        self.request_log = []

        # Setup session with retries
        self.session = requests.Session() if requests else None
        if self.session:
            retry = Retry(total=2, backoff_factor=0.5,
                         status_forcelist=[500, 502, 503, 504])
            adapter = HTTPAdapter(max_retries=retry)
            self.session.mount("https://", adapter)
            self.session.mount("http://", adapter)
            self.session.verify = False

            # Suppress SSL warnings
            import urllib3
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    def is_in_scope(self, url: str) -> bool:
        """Check if URL is within scope."""
        parsed = urlparse(url)
        host = parsed.hostname or ""

        for pattern in self.scope_domains:
            if pattern.startswith("*."):
                base = pattern[2:]
                if host == base or host.endswith(f".{base}"):
                    return True
            elif host == pattern:
                return True

        return False

    def _request(self, method: str, url: str,
                 headers: dict = None, **kwargs) -> Optional['requests.Response']:
        """Core request method with all safety checks."""
        # 1. Scope check
        if not self.is_in_scope(url):
            raise ValueError(f"OUT OF SCOPE: {url}")

        # 2. Circuit breaker check
        if not self.circuit_breaker.can_proceed():
            raise ConnectionError(
                f"CIRCUIT BREAKER OPEN — target rejecting requests. "
                f"Blocked {self.circuit_breaker.stats['total_blocked']} requests. "
                f"Will retry in {self.circuit_breaker.recovery_timeout}s.")

        # 3. Rate limit
        parsed = urlparse(url)
        self.rate_limiter.wait(parsed.hostname)

        # 4. Merge auth headers
        req_headers = {**self.auth_headers, **(headers or {})}

        # 5. Fire request
        t0 = time.time()
        try:
            resp = self.session.request(method, url, headers=req_headers,
                                       timeout=kwargs.pop("timeout", 10),
                                       **kwargs)
            elapsed = time.time() - t0

            # Log request
            self.request_log.append({
                "method": method, "url": url,
                "status": resp.status_code,
                "elapsed": round(elapsed, 2),
                "length": len(resp.content),
            })

            # Handle responses
            if resp.status_code == 429:
                self.rate_limiter.back_off(parsed.hostname)
                self.circuit_breaker.record_failure(429)
            elif resp.status_code in (403, 401):
                self.circuit_breaker.record_failure(resp.status_code)
            else:
                self.circuit_breaker.record_success()

            return resp

        except requests.exceptions.Timeout:
            self.circuit_breaker.record_failure()
            return None
        except Exception as e:
            self.circuit_breaker.record_failure()
            raise

    def get(self, url: str, **kwargs):
        return self._request("GET", url, **kwargs)

    def post(self, url: str, **kwargs):
        return self._request("POST", url, **kwargs)

    def put(self, url: str, **kwargs):
        return self._request("PUT", url, **kwargs)

    def delete(self, url: str, **kwargs):
        return self._request("DELETE", url, **kwargs)

    def patch(self, url: str, **kwargs):
        return self._request("PATCH", url, **kwargs)

    @property
    def stats(self) -> dict:
        """Get client stats."""
        return {
            "total_requests": len(self.request_log),
            "circuit_breaker": self.circuit_breaker.state,
            "blocked_requests": self.circuit_breaker.stats["total_blocked"],
            "dedup": self.dedup.stats,
        }
