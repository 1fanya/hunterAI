#!/usr/bin/env python3
"""
auth_manager.py — Automated Authentication for Bug Bounty Targets

Handles:
1. Credential-based login (username/password forms)
2. Token extraction from responses (cookies, JWT, Set-Cookie)
3. Session persistence across tools
4. OAuth flow detection

Usage:
    from auth_manager import AuthManager
    auth = AuthManager()
    session = auth.login("https://target.com/login", "user@test.com", "pass123")
    headers = auth.get_auth_headers()
"""
import json
import os
import re
import time
from http.cookiejar import MozillaCookieJar
from pathlib import Path
from urllib.parse import urlparse, urljoin

try:
    import requests
    from bs4 import BeautifulSoup
except ImportError:
    requests = None
    BeautifulSoup = None


class AuthManager:
    """Automated authentication manager for bug bounty targets."""

    def __init__(self, domain: str = "", data_dir: str = ""):
        self.domain = domain
        self.data_dir = Path(data_dir) if data_dir else Path(f"auth/{domain}")
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.session = requests.Session() if requests else None
        self.tokens = {}
        self.cookies = {}
        self.auth_type = "none"  # none, cookie, bearer, basic

        # Load saved session
        self._load_session()

    def _load_session(self):
        """Load persisted session data."""
        state_file = self.data_dir / "session.json"
        if state_file.exists():
            try:
                data = json.loads(state_file.read_text())
                self.tokens = data.get("tokens", {})
                self.cookies = data.get("cookies", {})
                self.auth_type = data.get("auth_type", "none")
            except Exception:
                pass

    def _save_session(self):
        """Persist session data."""
        state_file = self.data_dir / "session.json"
        state_file.write_text(json.dumps({
            "tokens": self.tokens,
            "cookies": self.cookies,
            "auth_type": self.auth_type,
            "timestamp": time.time(),
        }, indent=2))

    def detect_login_form(self, url: str) -> dict:
        """Detect login form on a page."""
        result = {
            "found": False,
            "action": "",
            "method": "POST",
            "fields": {},
            "csrf_token": "",
        }

        try:
            resp = self.session.get(url, timeout=10, verify=False)
            if not BeautifulSoup:
                return result

            soup = BeautifulSoup(resp.text, "html.parser")

            # Find login forms
            forms = soup.find_all("form")
            for form in forms:
                inputs = form.find_all("input")
                input_names = [inp.get("name", "").lower() for inp in inputs]

                # Check if this looks like a login form
                has_password = any("pass" in n for n in input_names)
                has_email_or_user = any(
                    any(k in n for k in ("email", "user", "login", "name"))
                    for n in input_names)

                if has_password and has_email_or_user:
                    result["found"] = True
                    result["action"] = urljoin(url,
                        form.get("action", url))
                    result["method"] = form.get("method", "POST").upper()

                    for inp in inputs:
                        name = inp.get("name", "")
                        inp_type = inp.get("type", "text").lower()
                        value = inp.get("value", "")

                        if inp_type == "hidden":
                            result["fields"][name] = value
                            # Detect CSRF token
                            if any(k in name.lower()
                                   for k in ("csrf", "token", "_token", "xsrf")):
                                result["csrf_token"] = value
                        elif "pass" in name.lower():
                            result["fields"][name] = "{PASSWORD}"
                        elif any(k in name.lower()
                                for k in ("email", "user", "login")):
                            result["fields"][name] = "{USERNAME}"
                        elif name:
                            result["fields"][name] = value

                    break  # Use first login form found

        except Exception:
            pass

        return result

    def login(self, login_url: str, username: str, password: str,
              form_data: dict = None) -> dict:
        """Perform login and extract tokens."""
        result = {
            "success": False,
            "auth_type": "none",
            "tokens": {},
            "error": "",
        }

        try:
            # Auto-detect form if not provided
            if not form_data:
                form_info = self.detect_login_form(login_url)
                if form_info["found"]:
                    form_data = {}
                    for key, val in form_info["fields"].items():
                        if val == "{USERNAME}":
                            form_data[key] = username
                        elif val == "{PASSWORD}":
                            form_data[key] = password
                        else:
                            form_data[key] = val
                    login_url = form_info["action"]
                else:
                    # Try common field names
                    form_data = {
                        "email": username,
                        "password": password,
                    }

            # Attempt login
            resp = self.session.post(
                login_url, data=form_data,
                timeout=15, verify=False, allow_redirects=True)

            # Extract auth tokens from response
            # 1. Cookies
            for cookie in self.session.cookies:
                self.cookies[cookie.name] = cookie.value
                if any(k in cookie.name.lower()
                       for k in ("session", "auth", "token", "jwt",
                                "sid", "phpsessid", "jsessionid")):
                    result["tokens"][cookie.name] = cookie.value
                    result["auth_type"] = "cookie"

            # 2. JWT in response body
            try:
                body = resp.json()
                for key in ("token", "access_token", "jwt",
                           "auth_token", "id_token"):
                    if key in body:
                        self.tokens["bearer"] = body[key]
                        result["tokens"]["bearer"] = body[key]
                        result["auth_type"] = "bearer"
                        break
            except Exception:
                pass

            # 3. JWT in Set-Cookie
            set_cookies = resp.headers.get("Set-Cookie", "")
            jwt_match = re.search(
                r'(eyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*)',
                set_cookies)
            if jwt_match:
                self.tokens["jwt"] = jwt_match.group(1)
                result["tokens"]["jwt"] = jwt_match.group(1)

            # Check if login succeeded
            if resp.status_code in (200, 201, 302):
                if result["tokens"]:
                    result["success"] = True
                elif self.session.cookies:
                    result["success"] = True
                    result["auth_type"] = "cookie"
                elif resp.status_code == 302:
                    # Redirect = likely successful login
                    result["success"] = True
                    result["auth_type"] = "cookie"

            self.auth_type = result["auth_type"]
            self._save_session()

        except Exception as e:
            result["error"] = str(e)

        return result

    def get_auth_headers(self) -> dict:
        """Get authentication headers for subsequent requests."""
        headers = {}

        # Bearer token
        if self.tokens.get("bearer"):
            headers["Authorization"] = f"Bearer {self.tokens['bearer']}"
        elif self.tokens.get("jwt"):
            headers["Authorization"] = f"Bearer {self.tokens['jwt']}"

        # Cookie header
        if self.cookies:
            cookie_str = "; ".join(f"{k}={v}" for k, v in self.cookies.items())
            headers["Cookie"] = cookie_str

        # From environment
        env_token = os.environ.get("HUNT_AUTH_TOKEN", "")
        if env_token and "Authorization" not in headers:
            headers["Authorization"] = (
                env_token if env_token.startswith("Bearer")
                else f"Bearer {env_token}")

        env_cookie = os.environ.get("HUNT_COOKIES", "")
        if env_cookie and "Cookie" not in headers:
            headers["Cookie"] = env_cookie

        return headers

    def register_account(self, register_url: str,
                         email: str, password: str,
                         extra_fields: dict = None) -> dict:
        """Auto-register a test account on the target."""
        result = {"success": False, "error": ""}

        common_payloads = [
            # Try JSON
            {"email": email, "password": password,
             "username": email.split("@")[0],
             **(extra_fields or {})},
            # Try form data with name
            {"email": email, "password": password,
             "password_confirmation": password,
             "name": "Security Test",
             **(extra_fields or {})},
        ]

        for payload in common_payloads:
            try:
                # Try JSON first
                resp = self.session.post(
                    register_url, json=payload,
                    timeout=15, verify=False)
                if resp.status_code in (200, 201, 302):
                    result["success"] = True
                    result["status"] = resp.status_code
                    return result

                # Try form data
                resp = self.session.post(
                    register_url, data=payload,
                    timeout=15, verify=False)
                if resp.status_code in (200, 201, 302):
                    result["success"] = True
                    result["status"] = resp.status_code
                    return result

            except Exception as e:
                result["error"] = str(e)

        return result

    def find_login_page(self, base_url: str) -> str:
        """Find the login page URL."""
        common_paths = [
            "/login", "/signin", "/sign-in", "/auth/login",
            "/account/login", "/api/auth/login",
            "/users/sign_in", "/session/new",
        ]

        for path in common_paths:
            url = base_url.rstrip("/") + path
            try:
                resp = self.session.get(url, timeout=5, verify=False,
                                       allow_redirects=False)
                if resp.status_code in (200, 302):
                    return url
            except Exception:
                continue

        return ""
