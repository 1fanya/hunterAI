#!/usr/bin/env python3
"""
browser_auto.py — Playwright Browser Automation

Automates complex auth flows, CSRF chains, screenshot-based PoCs,
and interactive testing that can't be done with curl.

Usage:
    from browser_auto import BrowserAuto
    auto = BrowserAuto()
    auto.login("https://target.com/login", "user", "pass")
    auto.screenshot_poc("https://target.com/admin", "admin_access.png")
"""
import json
import os
import time
from pathlib import Path

try:
    from playwright.sync_api import sync_playwright
    HAS_PLAYWRIGHT = True
except ImportError:
    HAS_PLAYWRIGHT = False


class BrowserAuto:
    """Playwright-based browser automation for bug bounty PoCs."""

    def __init__(self, headless: bool = True):
        self.headless = headless
        self.browser = None
        self.context = None
        self.page = None
        self.cookies = []
        self.available = HAS_PLAYWRIGHT

    def start(self) -> bool:
        """Start browser."""
        if not self.available:
            return False
        try:
            self._pw = sync_playwright().start()
            self.browser = self._pw.chromium.launch(headless=self.headless)
            self.context = self.browser.new_context(
                viewport={"width": 1920, "height": 1080},
                user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0")
            self.page = self.context.new_page()
            return True
        except Exception:
            return False

    def stop(self):
        """Close browser."""
        try:
            if self.browser:
                self.browser.close()
            if hasattr(self, '_pw'):
                self._pw.stop()
        except Exception:
            pass

    def login(self, login_url: str, username: str, password: str,
              username_selector: str = "input[name='username'],input[name='email'],input[type='email']",
              password_selector: str = "input[name='password'],input[type='password']",
              submit_selector: str = "button[type='submit'],input[type='submit']") -> bool:
        """Auto-login to a target."""
        try:
            self.page.goto(login_url, wait_until="networkidle", timeout=15000)
            self.page.fill(username_selector, username)
            self.page.fill(password_selector, password)
            self.page.click(submit_selector)
            self.page.wait_for_load_state("networkidle", timeout=10000)
            self.cookies = self.context.cookies()
            return True
        except Exception:
            return False

    def navigate(self, url: str, wait: str = "networkidle") -> dict:
        """Navigate to URL and return response info."""
        try:
            resp = self.page.goto(url, wait_until=wait, timeout=15000)
            return {
                "url": self.page.url,
                "status": resp.status if resp else 0,
                "title": self.page.title(),
                "content_length": len(self.page.content()),
            }
        except Exception as e:
            return {"error": str(e)}

    def screenshot_poc(self, url: str, filename: str,
                       output_dir: str = "findings/screenshots") -> str:
        """Take screenshot for PoC evidence."""
        Path(output_dir).mkdir(parents=True, exist_ok=True)
        filepath = str(Path(output_dir) / filename)
        try:
            self.page.goto(url, wait_until="networkidle", timeout=15000)
            self.page.screenshot(path=filepath, full_page=True)
            return filepath
        except Exception:
            return ""

    def capture_network(self, url: str, duration: int = 5) -> list:
        """Capture network requests for a page load."""
        requests_log = []

        def on_request(request):
            requests_log.append({
                "method": request.method,
                "url": request.url,
                "headers": dict(request.headers),
                "post_data": request.post_data,
            })

        def on_response(response):
            for req in requests_log:
                if req["url"] == response.url:
                    req["status"] = response.status
                    try:
                        req["response_headers"] = dict(response.headers)
                    except Exception:
                        pass

        self.page.on("request", on_request)
        self.page.on("response", on_response)
        self.page.goto(url, wait_until="networkidle", timeout=15000)
        time.sleep(duration)
        return requests_log

    def test_csrf(self, action_url: str, method: str = "POST",
                  data: dict = None) -> dict:
        """Test for CSRF by submitting a form without token."""
        try:
            # Create a page with a cross-origin form
            form_html = f'''
            <html><body>
            <form id="csrf" action="{action_url}" method="{method}">
            '''
            if data:
                for k, v in data.items():
                    form_html += f'<input name="{k}" value="{v}">'
            form_html += '</form><script>document.getElementById("csrf").submit();</script></body></html>'

            self.page.set_content(form_html)
            self.page.wait_for_load_state("networkidle", timeout=10000)

            return {
                "url": self.page.url,
                "title": self.page.title(),
                "csrf_possible": action_url not in self.page.url or "error" not in self.page.title().lower(),
            }
        except Exception as e:
            return {"error": str(e)}

    def test_oauth_bypass(self, auth_url: str) -> dict:
        """Test OAuth consent bypass (silent redirect)."""
        try:
            requests_log = []

            def on_response(response):
                requests_log.append({
                    "url": response.url,
                    "status": response.status,
                })

            self.page.on("response", on_response)
            self.page.goto(auth_url, wait_until="networkidle", timeout=15000)

            final_url = self.page.url
            has_code = "code=" in final_url
            consent_shown = "consent" in self.page.content().lower() or "allow" in self.page.content().lower()

            return {
                "auth_url": auth_url,
                "final_url": final_url,
                "redirects": requests_log,
                "has_code": has_code,
                "consent_shown": consent_shown,
                "bypass_possible": has_code and not consent_shown,
            }
        except Exception as e:
            return {"error": str(e)}

    def get_cookies(self) -> list:
        """Get all cookies from current context."""
        return self.context.cookies() if self.context else []

    def get_local_storage(self) -> dict:
        """Get localStorage contents."""
        try:
            return self.page.evaluate("() => { let o = {}; for(let i=0;i<localStorage.length;i++){let k=localStorage.key(i);o[k]=localStorage.getItem(k);} return o; }")
        except Exception:
            return {}

    def save_evidence(self, target: str, evidence_type: str, data: dict):
        """Save browser evidence."""
        out = Path(f"findings/{target}/browser")
        out.mkdir(parents=True, exist_ok=True)
        (out / f"{evidence_type}_{int(time.time())}.json").write_text(
            json.dumps(data, indent=2, default=str), encoding="utf-8")
