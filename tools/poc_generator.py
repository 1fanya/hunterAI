#!/usr/bin/env python3
"""
poc_generator.py — Automatic Proof-of-Concept Generator

Generates reproducible curl commands, Python scripts, and H1 report sections
from vulnerability findings. Makes reports triageable in minutes.

Usage:
    from poc_generator import PoCGenerator
    gen = PoCGenerator()
    poc = gen.generate(finding)
"""
import json
import os
import re
import textwrap
import time
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse, quote

# ── H1 Report Template ────────────────────────────────────────────────────────

H1_TEMPLATE = """## Summary
{summary}

## Severity
**{severity}** (CVSS {cvss})

## Steps to Reproduce

{steps}

## Proof of Concept

### cURL Command
```bash
{curl_command}
```

### Python Script
```python
{python_script}
```

## Impact
{impact}

## Suggested Fix
{fix}

## Supporting Material
- Response showing vulnerability: see attached
- Tested on: {tested_date}
{attachments}
"""


class PoCGenerator:
    """Generate reproducible PoC for vulnerability findings."""

    # CVSS base scores by vuln class
    CVSS_MAP = {
        "CRITICAL": "9.8",
        "HIGH": "8.1",
        "MEDIUM": "5.3",
        "LOW": "3.1",
    }

    def generate(self, finding: dict) -> dict:
        """Generate PoC from a finding dict."""
        vuln_type = self._detect_vuln_type(finding)
        url = finding.get("url", finding.get("endpoint", ""))
        method = finding.get("method", "GET")
        headers = finding.get("headers", {})
        body = finding.get("body", finding.get("data", ""))
        severity = finding.get("severity", "HIGH")

        curl = self._build_curl(url, method, headers, body)
        python = self._build_python(url, method, headers, body, vuln_type)
        report = self._build_report(finding, vuln_type, curl, python, severity)

        return {
            "vuln_type": vuln_type,
            "curl": curl,
            "python": python,
            "report": report,
            "severity": severity,
        }

    def generate_from_scanner_output(self, tool_name: str,
                                      output: str, url: str) -> dict:
        """Generate PoC from raw scanner output text."""
        finding = {
            "tool": tool_name,
            "url": url,
            "output": output,
            "method": "GET",
        }

        # Auto-detect severity from output
        output_lower = output.lower()
        if any(kw in output_lower for kw in ("critical", "rce", "injection confirmed")):
            finding["severity"] = "CRITICAL"
        elif any(kw in output_lower for kw in ("high", "idor", "ssrf", "sqli")):
            finding["severity"] = "HIGH"
        elif any(kw in output_lower for kw in ("medium", "xss", "cors")):
            finding["severity"] = "MEDIUM"
        else:
            finding["severity"] = "LOW"

        # Extract URLs from output
        urls = re.findall(r'https?://[^\s<>"\']+', output)
        if urls:
            finding["url"] = urls[0]

        return self.generate(finding)

    def _detect_vuln_type(self, finding: dict) -> str:
        """Detect vulnerability type from finding data."""
        text = json.dumps(finding).lower()
        type_map = [
            ("idor", ["idor", "bola", "object reference", "id swap"]),
            ("ssrf", ["ssrf", "server-side request", "metadata"]),
            ("sqli", ["sql injection", "sqli", "sqlmap", "injectable"]),
            ("xss", ["xss", "cross-site scripting"]),
            ("rce", ["rce", "remote code", "command injection"]),
            ("race", ["race condition", "limit-overrun", "double-spend"]),
            ("cache_poison", ["cache poison", "cache deception"]),
            ("proto_pollution", ["prototype pollution", "__proto__"]),
            ("auth_bypass", ["auth bypass", "bfla", "unauthorized"]),
            ("mass_assignment", ["mass assignment", "role=admin"]),
            ("cors", ["cors", "cross-origin"]),
            ("jwt", ["jwt", "json web token"]),
            ("open_redirect", ["open redirect", "redirect"]),
            ("ssti", ["ssti", "template injection"]),
        ]
        for vuln_type, keywords in type_map:
            if any(kw in text for kw in keywords):
                return vuln_type
        return "generic"

    def _build_curl(self, url: str, method: str = "GET",
                    headers: dict = None, body: str = "") -> str:
        """Build a curl command from request components."""
        parts = [f"curl -i -s -k"]

        if method != "GET":
            parts.append(f"-X {method}")

        for key, val in (headers or {}).items():
            parts.append(f"-H '{key}: {val}'")

        if body:
            if isinstance(body, dict):
                body = json.dumps(body)
            parts.append(f"-d '{body}'")

        parts.append(f"'{url}'")
        return " \\\n  ".join(parts)

    def _build_python(self, url: str, method: str = "GET",
                      headers: dict = None, body: str = "",
                      vuln_type: str = "generic") -> str:
        """Build a Python reproduction script."""
        headers_str = json.dumps(headers or {}, indent=4)
        body_line = ""
        if body:
            if isinstance(body, dict):
                body_line = f"\ndata = {json.dumps(body, indent=4)}"
            else:
                body_line = f'\ndata = {repr(body)}'

        script = textwrap.dedent(f"""\
            #!/usr/bin/env python3
            \"\"\"PoC for {vuln_type.upper()} vulnerability\"\"\"
            import requests
            import urllib3
            urllib3.disable_warnings()

            url = "{url}"
            headers = {headers_str}
            {body_line}

            # Send exploit request
            response = requests.{method.lower()}(
                url,
                headers=headers,
                {"json=data," if body and isinstance(body, dict) else "data=data," if body else ""}
                verify=False,
                timeout=15
            )

            print(f"Status: {{response.status_code}}")
            print(f"Length: {{len(response.text)}}")
            print(f"Body preview:")
            print(response.text[:1000])

            # Verify exploitation
            if response.status_code in (200, 201, 204):
                print("\\n[+] Vulnerability confirmed!")
            else:
                print(f"\\n[-] Got status {{response.status_code}}")
        """)
        return script.strip()

    def _build_report(self, finding: dict, vuln_type: str,
                      curl: str, python: str, severity: str) -> str:
        """Build H1-format report."""
        summaries = {
            "idor": "Broken Object Level Authorization allows accessing other users' data by modifying resource IDs.",
            "ssrf": "Server-Side Request Forgery allows making requests to internal services and cloud metadata.",
            "sqli": "SQL Injection allows extracting database contents via crafted input.",
            "xss": "Cross-Site Scripting allows executing arbitrary JavaScript in other users' browsers.",
            "rce": "Remote Code Execution allows running arbitrary commands on the server.",
            "race": "Race condition allows bypassing business logic through parallel requests.",
            "cache_poison": "Web cache poisoning allows serving malicious content to other users via CDN.",
            "auth_bypass": "Authentication bypass allows accessing protected resources without proper authorization.",
            "mass_assignment": "Mass assignment allows escalating privileges by injecting protected fields.",
        }

        impacts = {
            "idor": "An attacker can access, modify, or delete any user's data by enumerating resource IDs. This affects all users of the platform.",
            "ssrf": "An attacker can access internal services, cloud metadata (AWS/GCP/Azure credentials), and potentially achieve full infrastructure compromise.",
            "sqli": "An attacker can extract all data from the database including user credentials, PII, and sensitive business data.",
            "xss": "An attacker can steal session tokens, perform actions as the victim, or redirect users to malicious sites.",
            "rce": "An attacker can execute arbitrary commands on the server, leading to full system compromise, data exfiltration, and lateral movement.",
            "race": "An attacker can bypass single-use limitations, duplicate financial transactions, or manipulate application state.",
            "cache_poison": "An attacker can serve malicious content to all users visiting the poisoned URL, enabling mass XSS or phishing.",
            "auth_bypass": "An attacker can access administrative functionality and sensitive data without authentication.",
            "mass_assignment": "An attacker can escalate their role to admin, modify their subscription tier, or manipulate financial balances.",
        }

        fixes = {
            "idor": "Implement proper authorization checks on every API endpoint. Verify the requesting user owns the resource before returning or modifying it.",
            "ssrf": "Validate and whitelist allowed URLs. Block requests to internal IP ranges (10.x, 172.16-31.x, 192.168.x, 169.254.x). Use allowlist for protocols (HTTP/HTTPS only).",
            "sqli": "Use parameterized queries / prepared statements. Never concatenate user input into SQL queries.",
            "xss": "Encode all user-controlled output. Use Content-Security-Policy headers. Set HttpOnly flag on session cookies.",
            "rce": "Never pass user input to system commands. Use safe APIs instead of shell execution. Implement allowlists for file uploads.",
            "race": "Implement database-level locks or atomic operations for state-changing requests. Use idempotency keys.",
            "cache_poison": "Include all user-influenced headers in cache keys. Implement proper cache key normalization.",
            "auth_bypass": "Implement consistent authorization middleware across all endpoints. Use defense-in-depth with multiple auth layers.",
            "mass_assignment": "Use explicit allowlists for accepted fields in update/create operations. Never blindly merge user input into database records.",
        }

        url = finding.get("url", finding.get("endpoint", "unknown"))
        steps = f"1. Navigate to: `{url}`\n"
        steps += f"2. Run the following curl command:\n```bash\n{curl}\n```\n"
        steps += f"3. Observe the response showing the vulnerability."

        return H1_TEMPLATE.format(
            summary=summaries.get(vuln_type, f"Security vulnerability found at {url}"),
            severity=severity,
            cvss=self.CVSS_MAP.get(severity, "5.0"),
            steps=steps,
            curl_command=curl,
            python_script=python,
            impact=impacts.get(vuln_type, "An attacker can exploit this vulnerability to compromise user data or application integrity."),
            fix=fixes.get(vuln_type, "Implement proper input validation and authorization checks."),
            tested_date=datetime.now().strftime("%Y-%m-%d"),
            attachments="",
        )

    def save_poc(self, poc: dict, target: str, finding_id: str = "") -> dict:
        """Save PoC artifacts to disk."""
        fid = finding_id or str(int(time.time()))
        out_dir = Path(f"findings/{target}/poc/{fid}")
        out_dir.mkdir(parents=True, exist_ok=True)

        paths = {}

        # Save curl command
        curl_file = out_dir / "exploit.sh"
        curl_file.write_text(f"#!/bin/bash\n# PoC for {poc['vuln_type']}\n\n{poc['curl']}\n")
        paths["curl"] = str(curl_file)

        # Save Python script
        py_file = out_dir / "exploit.py"
        py_file.write_text(poc["python"])
        paths["python"] = str(py_file)

        # Save H1 report
        report_file = out_dir / "report.md"
        report_file.write_text(poc["report"])
        paths["report"] = str(report_file)

        return paths
