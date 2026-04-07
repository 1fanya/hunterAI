#!/usr/bin/env python3
"""
cert_monitor.py — Certificate Transparency Subdomain Monitor

Watches crt.sh for new subdomains in real-time.
New subdomain = unreviewed code = first-to-find opportunities.

Usage:
    from cert_monitor import CertMonitor
    cm = CertMonitor()
    new_subs = cm.check("target.com")
"""
import json
import os
import time
from pathlib import Path

try:
    import requests
except ImportError:
    requests = None


class CertMonitor:
    """Certificate Transparency subdomain discovery and monitoring."""

    CRT_SH = "https://crt.sh"

    def __init__(self, cache_dir: str = "hunt-memory/cert_cache"):
        self.cache_dir = Path(cache_dir)
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.session = requests.Session() if requests else None
        if self.session:
            self.session.headers["User-Agent"] = "HunterAI/1.0"

    def query_crtsh(self, domain: str) -> list:
        """Query crt.sh for all certificates for a domain."""
        try:
            resp = self.session.get(
                f"{self.CRT_SH}/?q=%25.{domain}&output=json",
                timeout=30)
            if resp.status_code != 200:
                return []
            return resp.json()
        except Exception:
            return []

    def extract_subdomains(self, domain: str) -> set:
        """Extract unique subdomains from certificate transparency logs."""
        certs = self.query_crtsh(domain)
        subdomains = set()

        for cert in certs:
            name = cert.get("name_value", "")
            for line in name.split("\n"):
                line = line.strip().lower()
                if line and line.endswith(domain) and "*" not in line:
                    subdomains.add(line)

        return subdomains

    def check(self, domain: str) -> dict:
        """Check for subdomains, compare with previous scan."""
        current = self.extract_subdomains(domain)
        cache_file = self.cache_dir / f"{domain}.json"

        previous = set()
        if cache_file.exists():
            try:
                data = json.loads(cache_file.read_text(encoding="utf-8"))
                previous = set(data.get("subdomains", []))
            except Exception:
                pass

        new_subs = current - previous
        removed = previous - current

        # Save current state
        cache_file.write_text(json.dumps({
            "subdomains": sorted(current),
            "last_check": time.strftime("%Y-%m-%d %H:%M:%S"),
            "total": len(current),
        }, indent=2), encoding="utf-8")

        return {
            "domain": domain,
            "total": len(current),
            "new": sorted(new_subs),
            "removed": sorted(removed),
            "new_count": len(new_subs),
            "all_subdomains": sorted(current),
        }

    def monitor_loop(self, domains: list, interval: int = 3600,
                     callback=None) -> None:
        """Continuously monitor domains for new subdomains."""
        while True:
            for domain in domains:
                result = self.check(domain)
                if result["new_count"] > 0 and callback:
                    callback(result)
            time.sleep(interval)
