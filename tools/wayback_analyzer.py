#!/usr/bin/env python3
"""
wayback_analyzer.py — Wayback Machine Diff Analyzer

Find removed endpoints, old API versions, debug pages, and admin panels
that were once live but removed (and may still work).

Usage:
    from wayback_analyzer import WaybackAnalyzer
    wa = WaybackAnalyzer()
    results = wa.analyze("target.com")
"""
import json
import re
import time
from pathlib import Path
from urllib.parse import urlparse

try:
    import requests
except ImportError:
    requests = None

WAYBACK_API = "https://web.archive.org/cdx/search/cdx"


class WaybackAnalyzer:
    """Wayback Machine historical analysis for bug bounty."""

    INTERESTING_PATTERNS = [
        (r'/api/', "API endpoint"),
        (r'/v\d+/', "Versioned API"),
        (r'/admin', "Admin panel"),
        (r'/debug', "Debug endpoint"),
        (r'/internal', "Internal endpoint"),
        (r'/graphql', "GraphQL endpoint"),
        (r'/swagger', "Swagger docs"),
        (r'/openapi', "OpenAPI spec"),
        (r'\.json$', "JSON config"),
        (r'\.xml$', "XML file"),
        (r'\.env', "Env file"),
        (r'\.git', "Git exposure"),
        (r'\.bak', "Backup file"),
        (r'\.sql', "SQL dump"),
        (r'\.log', "Log file"),
        (r'/config', "Config endpoint"),
        (r'/phpinfo', "PHP info"),
        (r'/server-status', "Server status"),
        (r'/wp-admin', "WordPress admin"),
        (r'/wp-json', "WordPress API"),
        (r'/actuator', "Spring Actuator"),
        (r'/metrics', "Metrics endpoint"),
        (r'/health', "Health check"),
        (r'/console', "Console/REPL"),
        (r'/test', "Test endpoint"),
        (r'/staging', "Staging"),
        (r'/dev', "Dev endpoint"),
        (r'/backup', "Backup"),
        (r'/dump', "Data dump"),
        (r'/reset', "Reset endpoint"),
    ]

    def __init__(self):
        self.session = requests.Session() if requests else None
        if self.session:
            self.session.headers["User-Agent"] = "HunterAI/1.0"

    def get_urls(self, domain: str, limit: int = 5000,
                 status_filter: str = "200") -> list:
        """Fetch historical URLs from Wayback Machine CDX API."""
        if not self.session:
            return []
        try:
            params = {
                "url": f"*.{domain}/*",
                "output": "json",
                "fl": "original,timestamp,statuscode,mimetype",
                "limit": limit,
                "collapse": "urlkey",
            }
            if status_filter:
                params["filter"] = f"statuscode:{status_filter}"

            resp = self.session.get(WAYBACK_API, params=params, timeout=30)
            if resp.status_code != 200:
                return []

            data = resp.json()
            if not data or len(data) < 2:
                return []

            # First row is headers
            headers = data[0]
            urls = []
            for row in data[1:]:
                entry = dict(zip(headers, row))
                urls.append({
                    "url": entry.get("original", ""),
                    "timestamp": entry.get("timestamp", ""),
                    "status": entry.get("statuscode", ""),
                    "mime": entry.get("mimetype", ""),
                })
            return urls
        except Exception as e:
            return []

    def find_interesting(self, domain: str) -> dict:
        """Find interesting historical URLs."""
        urls = self.get_urls(domain)
        results = {"domain": domain, "total_urls": len(urls),
                    "interesting": [], "endpoints": set(),
                    "removed_apis": [], "config_files": []}

        for entry in urls:
            url = entry["url"]
            path = urlparse(url).path.lower()

            for pattern, label in self.INTERESTING_PATTERNS:
                if re.search(pattern, path, re.IGNORECASE):
                    entry["type"] = label
                    results["interesting"].append(entry)
                    results["endpoints"].add(url)
                    break

        results["endpoints"] = sorted(results["endpoints"])
        return results

    def find_removed_endpoints(self, domain: str) -> list:
        """Find endpoints that were live historically but may be removed now."""
        historical = self.get_urls(domain, limit=2000)
        if not historical:
            return []

        # Get unique paths
        paths = set()
        for entry in historical:
            parsed = urlparse(entry["url"])
            paths.add(parsed.path)

        # Check which are interesting
        removed = []
        for path in sorted(paths):
            for pattern, label in self.INTERESTING_PATTERNS:
                if re.search(pattern, path, re.IGNORECASE):
                    removed.append({
                        "path": path,
                        "type": label,
                        "check_url": f"https://{domain}{path}",
                    })
                    break

        return removed

    def find_old_api_versions(self, domain: str) -> list:
        """Find old API versions that might still work."""
        urls = self.get_urls(domain)
        api_versions = {}

        for entry in urls:
            url = entry["url"]
            # Match /api/v1, /api/v2, /v1/, /v2/
            m = re.search(r'/(api/)?v(\d+)/', url, re.IGNORECASE)
            if m:
                version = int(m.group(2))
                base = url[:m.start()] + url[m.end():]
                if base not in api_versions:
                    api_versions[base] = set()
                api_versions[base].add(version)

        old_apis = []
        for base, versions in api_versions.items():
            if len(versions) > 1:
                latest = max(versions)
                for v in sorted(versions):
                    if v < latest:
                        old_apis.append({
                            "old_version": f"v{v}",
                            "latest_version": f"v{latest}",
                            "base_path": base,
                            "risk": "Old API versions often lack security patches",
                        })

        return old_apis

    def analyze(self, domain: str) -> dict:
        """Full Wayback analysis."""
        interesting = self.find_interesting(domain)
        removed = self.find_removed_endpoints(domain)
        old_apis = self.find_old_api_versions(domain)

        return {
            "domain": domain,
            "total_historical_urls": interesting["total_urls"],
            "interesting_endpoints": interesting["interesting"][:50],
            "removed_endpoints": removed[:30],
            "old_api_versions": old_apis,
            "unique_paths": len(interesting["endpoints"]),
        }

    def save_results(self, target: str, data: dict):
        out = Path(f"findings/{target}/wayback")
        out.mkdir(parents=True, exist_ok=True)
        (out / f"wayback_{int(time.time())}.json").write_text(
            json.dumps(data, indent=2, default=str), encoding="utf-8")
