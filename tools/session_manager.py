#!/usr/bin/env python3
"""
Session Manager — Authenticated session management for bug bounty hunting.

Handles login flows, stores cookies securely, and provides auth headers
to all other tools. Supports multiple auth types:
  - Cookie-based (PHPSESSID, _session, etc.)
  - Bearer tokens (JWT, API keys)
  - OAuth2 flows
  - Custom headers

Usage:
    # Store credentials from environment
    python3 session_manager.py --target target.com --cookie "session=abc123"
    python3 session_manager.py --target target.com --bearer "eyJ..."
    python3 session_manager.py --target target.com --login-url https://target.com/login \
        --username attacker@test.com --password xxx

    # In other tools:
    from session_manager import SessionManager
    sm = SessionManager("target.com")
    headers = sm.get_auth_headers("attacker")  # returns dict with auth headers
"""

import argparse
import hashlib
import json
import os
import sys
import time
from datetime import datetime, timezone
from urllib.parse import urlparse

try:
    import urllib.request
    import urllib.error
    import http.cookiejar
except ImportError:
    pass

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SESSIONS_DIR = os.path.join(BASE_DIR, "hunt-memory", "sessions")

GREEN = "\033[0;32m"
RED = "\033[0;31m"
YELLOW = "\033[1;33m"
CYAN = "\033[0;36m"
BOLD = "\033[1m"
NC = "\033[0m"


def log(level, msg):
    colors = {"ok": GREEN, "err": RED, "warn": YELLOW, "info": CYAN}
    symbols = {"ok": "+", "err": "-", "warn": "!", "info": "*"}
    print(f"{colors.get(level, '')}{BOLD}[{symbols.get(level, '*')}]{NC} {msg}")


class SessionManager:
    """Manages authenticated sessions for multiple accounts on a target.

    Stores sessions in hunt-memory/sessions/<target>_sessions.json.
    Credentials are stored with minimal exposure — cookies and tokens only,
    never raw passwords.
    """

    def __init__(self, target: str):
        self.target = target
        self.sessions_file = os.path.join(SESSIONS_DIR, f"{target}_sessions.json")
        self.sessions = {}  # role -> session_data
        self._load()

    def _load(self):
        """Load existing sessions from disk."""
        if os.path.exists(self.sessions_file):
            try:
                with open(self.sessions_file) as f:
                    self.sessions = json.load(f)
            except (json.JSONDecodeError, IOError):
                self.sessions = {}

    def save(self):
        """Save sessions to disk."""
        os.makedirs(os.path.dirname(self.sessions_file), exist_ok=True)
        with open(self.sessions_file, "w") as f:
            json.dump(self.sessions, f, indent=2)

    def add_cookie_session(self, role: str, cookies: str, headers: dict = None):
        """Add a cookie-based session.

        Args:
            role: 'attacker', 'victim', or custom role name
            cookies: Cookie string (e.g., "session=abc; csrf=xyz")
            headers: Additional headers to include with requests
        """
        self.sessions[role] = {
            "type": "cookie",
            "cookies": cookies,
            "headers": headers or {},
            "created_at": datetime.now(timezone.utc).isoformat(),
            "last_used": None,
            "request_count": 0,
        }
        self.save()
        log("ok", f"Session added: {role} (cookie-based)")

    def add_bearer_session(self, role: str, token: str, headers: dict = None):
        """Add a bearer token session.

        Args:
            role: 'attacker', 'victim', or custom role name
            token: Bearer token (JWT or API key)
            headers: Additional headers to include
        """
        self.sessions[role] = {
            "type": "bearer",
            "token": token,
            "headers": headers or {},
            "created_at": datetime.now(timezone.utc).isoformat(),
            "last_used": None,
            "request_count": 0,
        }
        self.save()
        log("ok", f"Session added: {role} (bearer token)")

    def add_custom_session(self, role: str, auth_headers: dict):
        """Add a session with custom auth headers.

        Args:
            role: 'attacker', 'victim', or custom role name
            auth_headers: Dict of headers to send (e.g., {"X-API-Key": "abc"})
        """
        self.sessions[role] = {
            "type": "custom",
            "headers": auth_headers,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "last_used": None,
            "request_count": 0,
        }
        self.save()
        log("ok", f"Session added: {role} (custom headers)")

    def login(self, role: str, login_url: str, username: str, password: str,
              csrf_field: str = None, method: str = "POST"):
        """Perform a login and capture session cookies.

        Args:
            role: 'attacker' or 'victim'
            login_url: Full URL to the login endpoint
            username: Username/email
            password: Password
            csrf_field: Name of CSRF token field if present
            method: HTTP method (POST by default)
        """
        try:
            cookie_jar = http.cookiejar.CookieJar()
            opener = urllib.request.build_opener(
                urllib.request.HTTPCookieProcessor(cookie_jar)
            )

            # Step 1: GET login page (capture CSRF + initial cookies)
            csrf_token = None
            if csrf_field:
                req = urllib.request.Request(login_url)
                req.add_header("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0")
                resp = opener.open(req, timeout=15)
                body = resp.read().decode("utf-8", errors="replace")

                # Extract CSRF token from form
                import re
                pattern = rf'name="{csrf_field}"[^>]*value="([^"]+)"'
                match = re.search(pattern, body, re.IGNORECASE)
                if match:
                    csrf_token = match.group(1)
                    log("info", f"CSRF token captured: {csrf_token[:20]}...")

            # Step 2: POST login credentials
            login_data = f"username={username}&password={password}"
            if csrf_token and csrf_field:
                login_data += f"&{csrf_field}={csrf_token}"

            req = urllib.request.Request(login_url, data=login_data.encode())
            req.add_header("Content-Type", "application/x-www-form-urlencoded")
            req.add_header("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0")

            try:
                resp = opener.open(req, timeout=15)
            except urllib.error.HTTPError as e:
                # 302 redirect after login is normal
                if e.code in (301, 302, 303):
                    pass
                else:
                    raise

            # Step 3: Extract cookies
            cookies = "; ".join(f"{c.name}={c.value}" for c in cookie_jar)
            if cookies:
                self.add_cookie_session(role, cookies)
                log("ok", f"Login successful for {role}: {len(list(cookie_jar))} cookies captured")
                return True
            else:
                log("err", f"Login failed for {role}: no cookies captured")
                return False

        except Exception as e:
            log("err", f"Login error: {e}")
            return False

    def get_auth_headers(self, role: str = "attacker") -> dict:
        """Get auth headers for a role. Returns empty dict if no session.

        Args:
            role: Session role name

        Returns:
            dict of HTTP headers to include in requests
        """
        session = self.sessions.get(role)
        if not session:
            return {}

        headers = dict(session.get("headers", {}))

        if session["type"] == "cookie":
            headers["Cookie"] = session["cookies"]
        elif session["type"] == "bearer":
            headers["Authorization"] = f"Bearer {session['token']}"
        # custom type already has headers set

        # Track usage
        session["last_used"] = datetime.now(timezone.utc).isoformat()
        session["request_count"] = session.get("request_count", 0) + 1

        return headers

    def get_token(self, role: str = "attacker") -> str:
        """Get raw token/cookie string for a role."""
        session = self.sessions.get(role)
        if not session:
            return ""

        if session["type"] == "bearer":
            return session["token"]
        elif session["type"] == "cookie":
            return session["cookies"]
        return ""

    def has_session(self, role: str) -> bool:
        """Check if a session exists for a role."""
        return role in self.sessions

    def list_sessions(self) -> list:
        """List all session roles."""
        result = []
        for role, data in self.sessions.items():
            result.append({
                "role": role,
                "type": data["type"],
                "created_at": data.get("created_at", "unknown"),
                "last_used": data.get("last_used"),
                "request_count": data.get("request_count", 0),
            })
        return result

    def validate_session(self, role: str, test_url: str) -> bool:
        """Check if a session is still valid by making a test request.

        Args:
            role: Session role to test
            test_url: URL that requires auth (should return 200 when authed)

        Returns:
            True if session is valid (got 200), False otherwise
        """
        headers = self.get_auth_headers(role)
        if not headers:
            return False

        try:
            req = urllib.request.Request(test_url)
            for k, v in headers.items():
                req.add_header(k, v)
            req.add_header("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0")

            resp = urllib.request.urlopen(req, timeout=10)
            valid = resp.getcode() == 200
            if valid:
                log("ok", f"Session valid: {role} → {resp.getcode()}")
            else:
                log("warn", f"Session may be expired: {role} → {resp.getcode()}")
            return valid
        except urllib.error.HTTPError as e:
            log("warn", f"Session check failed: {role} → {e.code}")
            return e.code not in (401, 403)
        except Exception as e:
            log("err", f"Session validation error: {e}")
            return False

    def delete_session(self, role: str):
        """Remove a session."""
        if role in self.sessions:
            del self.sessions[role]
            self.save()
            log("ok", f"Session removed: {role}")

    def print_summary(self):
        """Print session summary."""
        if not self.sessions:
            log("warn", f"No sessions for {self.target}")
            return

        print(f"\n{BOLD}Sessions for {self.target}{NC}")
        print(f"{'─' * 60}")
        for role, data in self.sessions.items():
            status = "🟢" if data.get("last_used") else "⚪"
            print(f"  {status} {role:12s}  type={data['type']:8s}  requests={data.get('request_count', 0)}")
        print()


def main():
    parser = argparse.ArgumentParser(description="Session Manager for Bug Bounty Hunting")
    parser.add_argument("--target", required=True, help="Target domain")
    parser.add_argument("--cookie", help="Cookie string for session")
    parser.add_argument("--bearer", help="Bearer token for session")
    parser.add_argument("--role", default="attacker", help="Session role (attacker/victim/custom)")
    parser.add_argument("--login-url", help="Login URL for credential-based login")
    parser.add_argument("--username", help="Username for login")
    parser.add_argument("--password", help="Password for login")
    parser.add_argument("--validate", help="URL to validate session against")
    parser.add_argument("--list", action="store_true", help="List all sessions")
    parser.add_argument("--delete", action="store_true", help="Delete session for role")
    parser.add_argument("--header", action="append", help="Custom header (key:value)")
    args = parser.parse_args()

    sm = SessionManager(args.target)

    if args.list:
        sm.print_summary()
        return

    if args.delete:
        sm.delete_session(args.role)
        return

    if args.validate:
        valid = sm.validate_session(args.role, args.validate)
        sys.exit(0 if valid else 1)

    custom_headers = {}
    if args.header:
        for h in args.header:
            k, v = h.split(":", 1)
            custom_headers[k.strip()] = v.strip()

    if args.cookie:
        sm.add_cookie_session(args.role, args.cookie, custom_headers)
    elif args.bearer:
        sm.add_bearer_session(args.role, args.bearer, custom_headers)
    elif args.login_url and args.username and args.password:
        sm.login(args.role, args.login_url, args.username, args.password)
    elif custom_headers:
        sm.add_custom_session(args.role, custom_headers)
    else:
        sm.print_summary()


if __name__ == "__main__":
    main()
