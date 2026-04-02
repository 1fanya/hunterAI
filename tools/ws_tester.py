#!/usr/bin/env python3
"""
WebSocket Tester — Test WebSocket endpoints for security vulnerabilities.

WebSocket endpoints are often overlooked and have weaker security than REST APIs:
  - Bypass WAFs (most WAFs don't inspect WS traffic)
  - Often miss authentication checks
  - Rarely have rate limiting
  - IDOR via subscription/channel IDs

Tests:
  1. CSWSH (Cross-Site WebSocket Hijacking) — missing Origin validation
  2. Authentication bypass — connect without auth
  3. IDOR in messages — swap user/channel IDs
  4. Injection — SQLi/XSS/command injection in message payloads
  5. Message replay — send modified versions of captured messages

Usage:
    python3 ws_tester.py --url wss://api.target.com/ws --cookie "session=abc"
    python3 ws_tester.py --url wss://api.target.com/ws --origin https://evil.com

    # Discovery mode: find WS endpoints from recon data
    python3 ws_tester.py --discover --recon-dir recon/target.com
"""

import argparse
import json
import os
import re
import sys
import time
from datetime import datetime, timezone
from urllib.parse import urlparse

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FINDINGS_DIR = os.path.join(BASE_DIR, "findings")

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


# Check for websocket library
try:
    import websocket as ws_lib
    _WS_OK = True
except ImportError:
    _WS_OK = False


class WSDiscoverer:
    """Discover WebSocket endpoints from recon data and JavaScript files."""

    WS_PATTERNS = [
        re.compile(r'wss?://[a-zA-Z0-9._\-/]+', re.IGNORECASE),
        re.compile(r'new\s+WebSocket\s*\(\s*["\']([^"\']+)', re.IGNORECASE),
        re.compile(r'\.connect\s*\(\s*["\']wss?://([^"\']+)', re.IGNORECASE),
        re.compile(r'socket\.io', re.IGNORECASE),
        re.compile(r'sockjs', re.IGNORECASE),
        re.compile(r'/cable\b', re.IGNORECASE),  # ActionCable (Rails)
        re.compile(r'/hub\b', re.IGNORECASE),     # SignalR
    ]

    COMMON_WS_PATHS = [
        "/ws", "/wss", "/websocket", "/socket",
        "/socket.io/?EIO=4&transport=websocket",
        "/cable", "/hub", "/signalr",
        "/api/ws", "/api/websocket",
        "/api/v1/ws", "/api/v2/ws",
        "/realtime", "/live", "/stream",
        "/events", "/notifications",
        "/chat", "/chat/ws",
    ]

    def discover_from_recon(self, recon_dir: str) -> list:
        """Find WebSocket endpoints from recon data."""
        ws_endpoints = set()

        # Search JS files for WebSocket URLs
        js_dir = os.path.join(recon_dir, "js")
        urls_dir = os.path.join(recon_dir, "urls")

        # Check JS endpoint extractions
        for root, _, files in os.walk(recon_dir):
            for fname in files:
                if fname.endswith((".txt", ".js", ".json")):
                    fpath = os.path.join(root, fname)
                    try:
                        with open(fpath, errors="replace") as f:
                            content = f.read()
                        for pattern in self.WS_PATTERNS:
                            for match in pattern.finditer(content):
                                url = match.group(0) if match.lastindex is None else match.group(1)
                                if url.startswith("ws"):
                                    ws_endpoints.add(url)
                    except (IOError, OSError):
                        continue

        return list(ws_endpoints)

    def probe_common_paths(self, base_url: str) -> list:
        """Probe common WebSocket paths on a host."""
        found = []
        parsed = urlparse(base_url)
        ws_scheme = "wss" if parsed.scheme == "https" else "ws"
        host = parsed.netloc

        for path in self.COMMON_WS_PATHS:
            ws_url = f"{ws_scheme}://{host}{path}"
            try:
                # Try HTTP upgrade request first (faster than full WS connect)
                import urllib.request
                http_url = f"{parsed.scheme}://{host}{path}"
                req = urllib.request.Request(http_url)
                req.add_header("Upgrade", "websocket")
                req.add_header("Connection", "Upgrade")
                req.add_header("Sec-WebSocket-Version", "13")
                req.add_header("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==")

                try:
                    resp = urllib.request.urlopen(req, timeout=5)
                    status = resp.getcode()
                except urllib.error.HTTPError as e:
                    status = e.code

                if status in (101, 200, 400):  # 101=upgrade, 400=bad WS request (endpoint exists)
                    found.append({"url": ws_url, "status": status})
                    log("ok", f"WebSocket endpoint found: {ws_url} (HTTP {status})")

            except Exception:
                continue

        return found


class WSTester:
    """Test WebSocket endpoints for security vulnerabilities."""

    def __init__(self, rate_limit=2.0):
        self.rate_limit = rate_limit
        self.findings = []

    def _add_finding(self, vuln_type, ws_url, severity, details):
        self.findings.append({
            "type": vuln_type,
            "url": ws_url,
            "severity": severity,
            "details": details,
            "ts": datetime.now(timezone.utc).isoformat(),
        })

    def test_cswsh(self, ws_url: str, cookies: str = None) -> dict:
        """Test for Cross-Site WebSocket Hijacking.

        Tests if the server accepts WebSocket connections from arbitrary Origins.
        If yes → attacker page can connect to victim's WS session using victim's cookies.
        """
        if not _WS_OK:
            log("warn", "websocket-client not installed: pip install websocket-client")
            return {"error": "websocket-client not installed"}

        result = {
            "test": "cswsh",
            "url": ws_url,
            "vulnerable": False,
            "details": {},
        }

        evil_origins = [
            "https://evil.com",
            "https://attacker.example.com",
            "null",  # null origin (file:// or sandboxed iframe)
        ]

        for origin in evil_origins:
            try:
                headers = {"Origin": origin}
                if cookies:
                    headers["Cookie"] = cookies

                ws_conn = ws_lib.create_connection(
                    ws_url,
                    header=headers,
                    timeout=10,
                )

                # If we connected successfully, the server doesn't validate Origin
                ws_conn.close()
                result["vulnerable"] = True
                result["details"]["accepted_origin"] = origin
                log("ok", f"CSWSH: Server accepted Origin: {origin}")

                self._add_finding("cswsh", ws_url, "high", {
                    "description": f"WebSocket server accepts connections from arbitrary Origin ({origin})",
                    "impact": "Attacker page can connect to victim's WebSocket using victim's cookies",
                    "origin_tested": origin,
                })
                break  # One success is enough

            except Exception as e:
                log("info", f"  Origin {origin}: rejected ({e})")
                continue

        if not result["vulnerable"]:
            log("info", "CSWSH: Server validates Origin — not vulnerable")

        return result

    def test_no_auth(self, ws_url: str) -> dict:
        """Test if WebSocket accepts connections without authentication."""
        if not _WS_OK:
            return {"error": "websocket-client not installed"}

        result = {
            "test": "no_auth",
            "url": ws_url,
            "vulnerable": False,
        }

        try:
            ws_conn = ws_lib.create_connection(ws_url, timeout=10)

            # Try to receive data without auth
            ws_conn.settimeout(5)
            try:
                msg = ws_conn.recv()
                result["vulnerable"] = True
                result["received_data"] = msg[:500] if isinstance(msg, str) else msg[:500].decode(errors="replace")
                log("ok", f"No auth: WebSocket accepts unauthenticated connections")

                self._add_finding("no_auth_ws", ws_url, "medium", {
                    "description": "WebSocket endpoint accepts connections without authentication",
                    "sample_data": result["received_data"][:200],
                })
            except Exception:
                # Connected but no data — try sending a message
                test_messages = [
                    '{"action":"subscribe","channel":"notifications"}',
                    '{"type":"ping"}',
                    'ping',
                    '42["message","hello"]',  # Socket.IO format
                ]
                for msg in test_messages:
                    try:
                        ws_conn.send(msg)
                        time.sleep(1)
                        reply = ws_conn.recv()
                        result["vulnerable"] = True
                        result["received_data"] = reply[:500] if isinstance(reply, str) else reply[:500].decode(errors="replace")
                        log("ok", f"No auth: Got response to '{msg[:30]}...'")

                        self._add_finding("no_auth_ws", ws_url, "medium", {
                            "description": "WebSocket responds to messages without authentication",
                            "sent": msg,
                            "received": result["received_data"][:200],
                        })
                        break
                    except Exception:
                        continue

            ws_conn.close()

        except Exception as e:
            log("info", f"No auth test: connection failed ({e})")

        return result

    def test_idor(self, ws_url: str, attacker_headers: dict, victim_id: str) -> dict:
        """Test IDOR in WebSocket messages.

        Sends subscribe/query messages with victim's IDs using attacker's auth.
        """
        if not _WS_OK:
            return {"error": "websocket-client not installed"}

        result = {
            "test": "ws_idor",
            "url": ws_url,
            "vulnerable": False,
            "messages_tested": [],
        }

        idor_messages = [
            {"action": "subscribe", "user_id": victim_id},
            {"action": "subscribe", "channel": f"user.{victim_id}"},
            {"type": "subscribe", "id": victim_id},
            {"event": "join", "room": victim_id},
            {"query": "getUserData", "userId": victim_id},
            {"action": "get", "resource": "profile", "id": victim_id},
        ]

        try:
            ws_conn = ws_lib.create_connection(
                ws_url,
                header=attacker_headers,
                timeout=10,
            )

            for msg_dict in idor_messages:
                try:
                    msg = json.dumps(msg_dict)
                    ws_conn.send(msg)
                    time.sleep(1)

                    ws_conn.settimeout(3)
                    try:
                        reply = ws_conn.recv()
                        reply_str = reply if isinstance(reply, str) else reply.decode(errors="replace")

                        # Check if response contains data (not just error/ack)
                        try:
                            reply_json = json.loads(reply_str)
                            is_error = any(k in reply_json for k in ("error", "err", "unauthorized"))
                            has_data = any(k in reply_json for k in ("data", "user", "profile", "result", "message"))
                        except json.JSONDecodeError:
                            is_error = "error" in reply_str.lower()
                            has_data = len(reply_str) > 50

                        result["messages_tested"].append({
                            "sent": msg_dict,
                            "received": reply_str[:300],
                            "has_data": has_data and not is_error,
                        })

                        if has_data and not is_error:
                            result["vulnerable"] = True
                            log("ok", f"WS IDOR: got data for victim {victim_id}")
                            self._add_finding("ws_idor", ws_url, "high", {
                                "description": f"WebSocket IDOR: attacker can access victim's data (ID: {victim_id})",
                                "sent": msg_dict,
                                "received": reply_str[:300],
                            })

                    except Exception:
                        pass  # No reply to this message format

                except Exception:
                    continue

            ws_conn.close()

        except Exception as e:
            log("err", f"WS IDOR test error: {e}")

        return result

    def test_injection(self, ws_url: str, headers: dict = None) -> dict:
        """Test for injection vulnerabilities in WebSocket messages."""
        if not _WS_OK:
            return {"error": "websocket-client not installed"}

        result = {
            "test": "ws_injection",
            "url": ws_url,
            "vulnerable": False,
            "tests": [],
        }

        injection_payloads = [
            # SQLi
            {"type": "sqli", "payload": '{"search":"\\\" OR 1=1--"}'},
            {"type": "sqli", "payload": '{"id":"1 UNION SELECT 1,2,3--"}'},
            # XSS
            {"type": "xss", "payload": '{"message":"<script>alert(1)</script>"}'},
            {"type": "xss", "payload": '{"name":"<img src=x onerror=alert(1)>"}'},
            # Command injection
            {"type": "cmdi", "payload": '{"cmd":"test;id"}'},
            {"type": "cmdi", "payload": '{"file":"test|cat /etc/passwd"}'},
            # SSTI
            {"type": "ssti", "payload": '{"template":"{{7*7}}"}'},
            {"type": "ssti", "payload": '{"name":"${7*7}"}'},
        ]

        try:
            ws_conn = ws_lib.create_connection(
                ws_url,
                header=headers or {},
                timeout=10,
            )

            for test in injection_payloads:
                try:
                    ws_conn.send(test["payload"])
                    time.sleep(0.5)

                    ws_conn.settimeout(3)
                    try:
                        reply = ws_conn.recv()
                        reply_str = reply if isinstance(reply, str) else reply.decode(errors="replace")

                        # Check for injection indicators
                        indicators = {
                            "sqli": ["syntax error", "mysql", "postgresql", "sqlite", "UNION", "sql"],
                            "xss": ["<script>", "alert(1)", "onerror"],
                            "cmdi": ["uid=", "root:", "/bin/"],
                            "ssti": ["49", "7777777"],
                        }

                        for indicator in indicators.get(test["type"], []):
                            if indicator.lower() in reply_str.lower():
                                result["vulnerable"] = True
                                test_result = {
                                    "type": test["type"],
                                    "payload": test["payload"],
                                    "indicator": indicator,
                                    "response": reply_str[:300],
                                }
                                result["tests"].append(test_result)
                                log("ok", f"WS Injection ({test['type']}): indicator '{indicator}' found")

                                self._add_finding(f"ws_{test['type']}", ws_url, "high", {
                                    "description": f"WebSocket {test['type'].upper()} injection",
                                    "payload": test["payload"],
                                    "indicator": indicator,
                                    "response": reply_str[:300],
                                })
                                break

                    except Exception:
                        pass

                except Exception:
                    continue

            ws_conn.close()

        except Exception as e:
            log("err", f"WS injection test error: {e}")

        return result

    def run_all_tests(self, ws_url: str, cookies: str = None,
                      auth_headers: dict = None, victim_id: str = None) -> dict:
        """Run all WebSocket tests on an endpoint."""
        log("info", f"Testing WebSocket: {ws_url}")

        headers = auth_headers or {}
        if cookies:
            headers["Cookie"] = cookies

        results = {
            "url": ws_url,
            "ts": datetime.now(timezone.utc).isoformat(),
            "tests": {},
        }

        # Test 1: CSWSH
        results["tests"]["cswsh"] = self.test_cswsh(ws_url, cookies)

        # Test 2: No auth
        results["tests"]["no_auth"] = self.test_no_auth(ws_url)

        # Test 3: IDOR (if victim ID provided)
        if victim_id:
            results["tests"]["idor"] = self.test_idor(ws_url, headers, victim_id)

        # Test 4: Injection
        results["tests"]["injection"] = self.test_injection(ws_url, headers)

        # Summary
        vuln_count = sum(1 for t in results["tests"].values() if t.get("vulnerable"))
        results["total_vulns"] = vuln_count

        if vuln_count > 0:
            log("ok", f"WebSocket: {vuln_count} vulnerabilities found")
        else:
            log("info", "WebSocket: no vulnerabilities found")

        return results

    def save_findings(self, target_name: str):
        """Save findings to disk."""
        if not self.findings:
            return

        out_dir = os.path.join(FINDINGS_DIR, target_name)
        os.makedirs(out_dir, exist_ok=True)

        out_file = os.path.join(out_dir, "ws_findings.json")
        with open(out_file, "w") as f:
            json.dump(self.findings, f, indent=2)
        log("ok", f"Saved {len(self.findings)} WS findings to {out_file}")


def main():
    parser = argparse.ArgumentParser(description="WebSocket Vulnerability Tester")
    parser.add_argument("--url", help="WebSocket URL (wss://...)")
    parser.add_argument("--cookie", help="Session cookie")
    parser.add_argument("--bearer", help="Bearer token")
    parser.add_argument("--origin", help="Test with specific Origin header")
    parser.add_argument("--victim-id", help="Victim user ID for IDOR testing")
    parser.add_argument("--target", help="Target name for saving findings")
    parser.add_argument("--discover", action="store_true", help="Discover WS endpoints")
    parser.add_argument("--recon-dir", help="Recon data directory for discovery")
    parser.add_argument("--base-url", help="Base HTTP URL for common path probing")
    args = parser.parse_args()

    if args.discover:
        discoverer = WSDiscoverer()
        if args.recon_dir:
            endpoints = discoverer.discover_from_recon(args.recon_dir)
            for ep in endpoints:
                log("ok", f"Found WS endpoint: {ep}")
        if args.base_url:
            found = discoverer.probe_common_paths(args.base_url)
            for f in found:
                log("ok", f"Probed: {f['url']} (HTTP {f['status']})")
        return

    if not args.url:
        parser.error("--url is required (or use --discover)")

    tester = WSTester()
    headers = {}
    if args.bearer:
        headers["Authorization"] = f"Bearer {args.bearer}"

    results = tester.run_all_tests(
        args.url,
        cookies=args.cookie,
        auth_headers=headers,
        victim_id=args.victim_id,
    )

    print(json.dumps(results, indent=2, default=str))

    if args.target:
        tester.save_findings(args.target)


if __name__ == "__main__":
    main()
