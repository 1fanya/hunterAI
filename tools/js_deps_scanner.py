#!/usr/bin/env python3
"""
js_deps_scanner.py — JavaScript Dependency Vulnerability Scanner

Extract npm/JS library versions from JS bundles and check for known
vulnerable versions (prototype pollution, XSS, RCE, etc.)

Usage:
    from js_deps_scanner import JSDepsScanner
    scanner = JSDepsScanner()
    vulns = scanner.scan_url("https://target.com")
"""
import json
import re
import time
from pathlib import Path

try:
    import requests
except ImportError:
    requests = None

# Known vulnerable JS library versions (curated high-impact list)
KNOWN_VULNS = {
    "jquery": [
        {"below": "3.5.0", "cve": "CVE-2020-11022", "severity": "MEDIUM",
         "desc": "XSS via HTML passed to DOM manipulation methods"},
        {"below": "3.0.0", "cve": "CVE-2015-9251", "severity": "MEDIUM",
         "desc": "XSS in cross-domain ajax requests"},
    ],
    "lodash": [
        {"below": "4.17.21", "cve": "CVE-2021-23337", "severity": "HIGH",
         "desc": "Command injection via template function"},
        {"below": "4.17.12", "cve": "CVE-2019-10744", "severity": "CRITICAL",
         "desc": "Prototype pollution in defaultsDeep"},
    ],
    "angular": [
        {"below": "1.6.9", "cve": "CVE-2022-25869", "severity": "MEDIUM",
         "desc": "XSS via $sanitize bypass"},
    ],
    "react": [
        {"below": "16.4.2", "cve": "CVE-2018-6341", "severity": "MEDIUM",
         "desc": "XSS via SSR attribute injection"},
    ],
    "vue": [
        {"below": "2.5.17", "cve": "CVE-2018-11235", "severity": "MEDIUM",
         "desc": "XSS via v-bind"},
    ],
    "bootstrap": [
        {"below": "3.4.0", "cve": "CVE-2018-14040", "severity": "MEDIUM",
         "desc": "XSS in data-target attribute"},
    ],
    "moment": [
        {"below": "2.29.4", "cve": "CVE-2022-31129", "severity": "HIGH",
         "desc": "ReDoS in string parsing"},
    ],
    "handlebars": [
        {"below": "4.7.7", "cve": "CVE-2021-23369", "severity": "CRITICAL",
         "desc": "Remote code execution via template compilation"},
    ],
    "axios": [
        {"below": "1.6.0", "cve": "CVE-2023-45857", "severity": "MEDIUM",
         "desc": "CSRF token leakage via headers"},
    ],
    "express": [
        {"below": "4.19.2", "cve": "CVE-2024-29041", "severity": "MEDIUM",
         "desc": "Open redirect via malicious URL"},
    ],
    "dompurify": [
        {"below": "2.4.1", "cve": "CVE-2023-24816", "severity": "MEDIUM",
         "desc": "Mutation XSS bypass"},
    ],
    "marked": [
        {"below": "4.0.10", "cve": "CVE-2022-21680", "severity": "HIGH",
         "desc": "ReDoS in heading parsing"},
    ],
}


class JSDepsScanner:
    """Scan JS bundles for vulnerable library versions."""

    VERSION_PATTERNS = [
        # Library comment headers
        (r'/\*[!*]\s*(jQuery)\s+v?([\d.]+)', "jquery"),
        (r'(lodash)\s+v?([\d.]+)', "lodash"),
        (r'(AngularJS|angular)\s+v?([\d.]+)', "angular"),
        (r'(React)\s+v?([\d.]+)', "react"),
        (r'(Vue\.js|vue)\s+v?([\d.]+)', "vue"),
        (r'(Bootstrap)\s+v?([\d.]+)', "bootstrap"),
        (r'(moment)\s+v?([\d.]+)', "moment"),
        (r'(Handlebars)\s+v?([\d.]+)', "handlebars"),
        (r'(axios)\s+v?([\d.]+)', "axios"),
        (r'(DOMPurify)\s+v?([\d.]+)', "dompurify"),
        (r'(marked)\s+v?([\d.]+)', "marked"),
        # Generic version assignment
        (r'(?:VERSION|version)\s*[:=]\s*["\'](\w+)/([\d.]+)["\']', None),
        # Package.json embedded
        (r'"name"\s*:\s*"([^"]+)"[^}]*"version"\s*:\s*"([\d.]+)"', None),
    ]

    def __init__(self):
        self.session = requests.Session() if requests else None
        if self.session:
            self.session.headers["User-Agent"] = "Mozilla/5.0 Chrome/120.0"
            self.session.verify = False

    def extract_versions(self, js_content: str) -> list:
        """Extract library versions from JS content."""
        found = []
        seen = set()

        for pattern, lib_key in self.VERSION_PATTERNS:
            for m in re.finditer(pattern, js_content, re.IGNORECASE):
                lib = lib_key or m.group(1).lower()
                version = m.group(2)
                key = f"{lib}/{version}"
                if key not in seen:
                    seen.add(key)
                    found.append({"library": lib, "version": version})

        return found

    def check_vulns(self, library: str, version: str) -> list:
        """Check if a library version has known vulnerabilities."""
        lib_key = library.lower().strip()
        vulns = KNOWN_VULNS.get(lib_key, [])
        matches = []

        for vuln in vulns:
            try:
                if self._version_lt(version, vuln["below"]):
                    matches.append({
                        "library": library,
                        "version": version,
                        "vulnerable_below": vuln["below"],
                        "cve": vuln.get("cve", ""),
                        "severity": vuln["severity"],
                        "description": vuln["desc"],
                    })
            except Exception:
                continue

        return matches

    @staticmethod
    def _version_lt(a: str, b: str) -> bool:
        """Check if version a < version b."""
        def parts(v):
            return [int(x) for x in re.findall(r'\d+', v)]
        return parts(a) < parts(b)

    def scan_url(self, url: str) -> dict:
        """Scan a URL's JS files for vulnerable dependencies."""
        result = {"url": url, "libraries": [], "vulnerabilities": []}

        try:
            resp = self.session.get(url, timeout=15)
            if resp.status_code != 200:
                return result

            # Find JS file URLs
            js_urls = set()
            for m in re.finditer(r'<script[^>]+src=["\']([^"\']+\.js[^"\']*)["\']',
                                  resp.text, re.IGNORECASE):
                from urllib.parse import urljoin
                js_urls.add(urljoin(url, m.group(1)))

            # Analyze each JS file
            for js_url in list(js_urls)[:20]:
                try:
                    js_resp = self.session.get(js_url, timeout=10)
                    if js_resp.status_code == 200:
                        versions = self.extract_versions(js_resp.text)
                        for v in versions:
                            v["source"] = js_url
                            result["libraries"].append(v)
                            vulns = self.check_vulns(v["library"], v["version"])
                            result["vulnerabilities"].extend(vulns)
                except Exception:
                    continue

            # Also check inline scripts
            versions = self.extract_versions(resp.text)
            for v in versions:
                v["source"] = "inline"
                result["libraries"].append(v)
                vulns = self.check_vulns(v["library"], v["version"])
                result["vulnerabilities"].extend(vulns)

        except Exception:
            pass

        return result
