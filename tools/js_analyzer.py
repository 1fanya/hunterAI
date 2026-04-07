#!/usr/bin/env python3
"""
js_analyzer.py — JavaScript Source Map & Endpoint Analyzer

Deobfuscates JS bundles, extracts hidden API endpoints, secrets,
internal paths, and developer comments that reveal attack surface.

Usage:
    from js_analyzer import JSAnalyzer
    analyzer = JSAnalyzer("https://target.com")
    results = analyzer.analyze_all()
"""
import json
import os
import re
import time
from pathlib import Path
from urllib.parse import urljoin, urlparse

try:
    import requests
except ImportError:
    requests = None


class JSAnalyzer:
    """JavaScript source analyzer for bug bounty hunting."""

    API_PATTERNS = [
        r'["\']/(api|v\d|graphql|rest|internal|admin|auth|oauth|ws)/[^"\']*["\']',
        r'["\']https?://[^"\']+/api/[^"\']*["\']',
        r'fetch\s*\(\s*["\']([^"\']+)["\']',
        r'axios\.\w+\s*\(\s*["\']([^"\']+)["\']',
        r'\.get\s*\(\s*["\']([^"\']+)["\']',
        r'\.post\s*\(\s*["\']([^"\']+)["\']',
        r'\.put\s*\(\s*["\']([^"\']+)["\']',
        r'\.delete\s*\(\s*["\']([^"\']+)["\']',
        r'XMLHttpRequest.*open\s*\(["\'](?:GET|POST|PUT|DELETE)["\']\s*,\s*["\']([^"\']+)',
        r'url:\s*["\']([^"\']+)["\']',
        r'endpoint:\s*["\']([^"\']+)["\']',
        r'baseURL:\s*["\']([^"\']+)["\']',
    ]

    SECRET_PATTERNS = [
        (r'["\'](?:api[_-]?key|apikey|api[_-]?token)["\']?\s*[:=]\s*["\']([^"\']{10,})["\']', "API Key"),
        (r'["\'](?:secret|password|passwd|pwd|token)["\']?\s*[:=]\s*["\']([^"\']{6,})["\']', "Secret"),
        (r'(?:aws_access_key_id|AKIA)[A-Z0-9]{16,}', "AWS Key"),
        (r'(?:ghp_|github_pat_)[A-Za-z0-9_]{36,}', "GitHub Token"),
        (r'sk-[A-Za-z0-9]{32,}', "OpenAI/Stripe Key"),
        (r'eyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*', "JWT"),
        (r'(?:mongodb|postgres|mysql|redis)://[^\s"\']+', "DB URL"),
        (r'-----BEGIN (?:RSA |EC )?PRIVATE KEY-----', "Private Key"),
    ]

    SINK_PATTERNS = [
        (r'eval\s*\(', "eval() — code injection sink"),
        (r'innerHTML\s*=', "innerHTML — XSS sink"),
        (r'document\.write\s*\(', "document.write — XSS sink"),
        (r'\.html\s*\(', "jQuery .html() — XSS sink"),
        (r'window\.location\s*=', "location = open redirect sink"),
        (r'postMessage\s*\(', "postMessage — XSS vector"),
        (r'dangerouslySetInnerHTML', "React XSS risk"),
        (r'__NEXT_DATA__', "Next.js data leak"),
        (r'localStorage\.(set|get)Item\s*\(\s*["\'](?:token|session|auth)', "Token in localStorage"),
    ]

    def __init__(self, base_url: str = ""):
        self.base_url = base_url.rstrip("/")
        self.session = requests.Session() if requests else None
        if self.session:
            self.session.headers["User-Agent"] = (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0")
            self.session.verify = False
        self.endpoints = set()
        self.secrets = []
        self.findings = []

    def discover_js_files(self, urls: list = None) -> list:
        js_files = set()
        for page_url in (urls or [self.base_url])[:10]:
            try:
                resp = self.session.get(page_url, timeout=10)
                for m in re.finditer(r'<script[^>]+src=["\']([^"\']+\.js[^"\']*)["\']',
                                     resp.text, re.IGNORECASE):
                    js_files.add(urljoin(page_url, m.group(1)))
                for m in re.finditer(r'["\']([^"\']*(?:bundle|chunk|app|main|vendor)[^"\']*\.js)["\']',
                                     resp.text):
                    js_files.add(urljoin(page_url, m.group(1)))
            except Exception:
                continue
        return list(js_files)

    def fetch_source_map(self, js_url: str) -> str:
        try:
            resp = self.session.get(js_url, timeout=10)
            if resp.status_code != 200:
                return ""
            m = re.search(r'//[#@]\s*sourceMappingURL\s*=\s*(\S+)', resp.text)
            if m:
                map_resp = self.session.get(urljoin(js_url, m.group(1)), timeout=10)
                if map_resp.status_code == 200:
                    self.findings.append({"type": "source_map_exposed",
                                          "severity": "MEDIUM", "url": urljoin(js_url, m.group(1))})
                    return map_resp.text
            map_resp = self.session.get(js_url + ".map", timeout=8)
            if map_resp.status_code == 200 and "sources" in map_resp.text:
                self.findings.append({"type": "source_map_exposed",
                                      "severity": "MEDIUM", "url": js_url + ".map"})
                return map_resp.text
        except Exception:
            pass
        return ""

    def analyze_js(self, js_url: str) -> dict:
        result = {"url": js_url, "endpoints": [], "secrets": [], "sinks": []}
        try:
            resp = self.session.get(js_url, timeout=15)
            if resp.status_code != 200:
                return result

            content = resp.text
            sm = self.fetch_source_map(js_url)
            if sm:
                try:
                    for src in json.loads(sm).get("sourcesContent", []):
                        if src:
                            content += "\n" + src
                except Exception:
                    pass

            for pat in self.API_PATTERNS:
                for m in re.finditer(pat, content):
                    ep = m.group(1) if m.lastindex else m.group(0)
                    ep = ep.strip("\"'")
                    if ep and len(ep) > 3:
                        result["endpoints"].append(ep)
                        self.endpoints.add(ep)

            for pat, label in self.SECRET_PATTERNS:
                for m in re.finditer(pat, content):
                    val = m.group(1) if m.lastindex else m.group(0)
                    s = {"type": label, "value": val[:50] + "...", "source": js_url}
                    result["secrets"].append(s)
                    self.secrets.append(s)
                    self.findings.append({"type": "secret_in_js", "severity": "HIGH",
                                          "detail": f"{label} in {os.path.basename(js_url)}", "url": js_url})

            for pat, label in self.SINK_PATTERNS:
                n = len(re.findall(pat, content))
                if n:
                    result["sinks"].append({"type": label, "count": n})
        except Exception:
            pass
        return result

    def analyze_all(self, urls: list = None) -> dict:
        js_files = self.discover_js_files(urls)
        results = {"base_url": self.base_url, "js_files": len(js_files),
                    "analyzed": [], "endpoints": [], "secrets": [], "findings": []}
        for url in js_files[:30]:
            a = self.analyze_js(url)
            if a["endpoints"] or a["secrets"] or a["sinks"]:
                results["analyzed"].append(a)
            time.sleep(0.3)
        results["endpoints"] = sorted(self.endpoints)
        results["secrets"] = self.secrets
        results["findings"] = self.findings
        return results

    def save_results(self, target: str):
        out = Path(f"findings/{target}/js_analysis")
        out.mkdir(parents=True, exist_ok=True)
        (out / f"js_{int(time.time())}.json").write_text(
            json.dumps({"endpoints": sorted(self.endpoints), "secrets": self.secrets,
                         "findings": self.findings}, indent=2, default=str), encoding="utf-8")
