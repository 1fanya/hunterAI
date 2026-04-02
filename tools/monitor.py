#!/usr/bin/env python3
"""
monitor.py — Continuous Attack Surface Monitor

Watches for new subdomains, endpoints, and certificates.
Alerts when attack surface changes — catch new features before other hunters.

Usage:
    python3 monitor.py --domain target.com --interval 3600
"""
import json
import os
import hashlib
import subprocess
import time
from datetime import datetime
from pathlib import Path

try:
    import requests
except ImportError:
    requests = None


class AttackSurfaceMonitor:
    """Monitor attack surface for changes."""

    def __init__(self, domain: str, data_dir: str = ""):
        self.domain = domain
        self.data_dir = Path(data_dir) if data_dir else Path(f"monitor/{domain}")
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.state_file = self.data_dir / "state.json"
        self.state = self._load_state()
        self.changes = []

    def _load_state(self) -> dict:
        """Load previous monitoring state."""
        if self.state_file.exists():
            try:
                return json.loads(self.state_file.read_text())
            except Exception:
                pass
        return {
            "subdomains": [],
            "endpoints": [],
            "technologies": [],
            "response_hashes": {},
            "last_scan": None,
        }

    def _save_state(self) -> None:
        """Save current monitoring state."""
        self.state["last_scan"] = datetime.now().isoformat()
        self.state_file.write_text(json.dumps(self.state, indent=2))

    def check_subdomains(self) -> dict:
        """Check for new subdomains since last scan."""
        result = {"new": [], "removed": [], "total": 0}
        current_subs = set()

        # Use subfinder
        try:
            proc = subprocess.run(
                ["subfinder", "-d", self.domain, "-silent"],
                capture_output=True, text=True, timeout=120)
            if proc.returncode == 0:
                current_subs.update(proc.stdout.strip().splitlines())
        except Exception:
            pass

        # Use crt.sh
        try:
            resp = requests.get(
                f"https://crt.sh/?q=%.{self.domain}&output=json", timeout=15)
            if resp.status_code == 200:
                for entry in resp.json():
                    name = entry.get("name_value", "")
                    for sub in name.split("\n"):
                        sub = sub.strip().lower()
                        if sub.endswith(self.domain):
                            current_subs.add(sub)
        except Exception:
            pass

        previous_subs = set(self.state.get("subdomains", []))
        result["new"] = sorted(current_subs - previous_subs)
        result["removed"] = sorted(previous_subs - current_subs)
        result["total"] = len(current_subs)

        if result["new"]:
            self.changes.append({
                "type": "new_subdomains",
                "count": len(result["new"]),
                "subdomains": result["new"],
                "timestamp": datetime.now().isoformat(),
            })

        self.state["subdomains"] = sorted(current_subs)
        return result

    def check_endpoints(self, urls: list[str] = None) -> dict:
        """Check for new/changed endpoints."""
        result = {"new": [], "changed": [], "down": []}

        urls = urls or [f"https://{sub}" for sub in self.state.get("subdomains", [])[:50]]
        previous_hashes = self.state.get("response_hashes", {})
        current_hashes = {}

        for url in urls[:100]:
            try:
                resp = requests.get(url, timeout=8, allow_redirects=True,
                                   verify=False)
                body_hash = hashlib.md5(resp.text[:5000].encode()).hexdigest()
                current_hashes[url] = {
                    "hash": body_hash,
                    "status": resp.status_code,
                    "length": len(resp.text),
                }

                prev = previous_hashes.get(url)
                if prev is None:
                    result["new"].append({
                        "url": url,
                        "status": resp.status_code,
                        "length": len(resp.text),
                    })
                elif prev.get("hash") != body_hash:
                    result["changed"].append({
                        "url": url,
                        "old_hash": prev.get("hash"),
                        "new_hash": body_hash,
                        "old_length": prev.get("length"),
                        "new_length": len(resp.text),
                    })
            except Exception:
                if url in previous_hashes:
                    result["down"].append(url)

        if result["new"] or result["changed"]:
            self.changes.append({
                "type": "endpoint_changes",
                "new_count": len(result["new"]),
                "changed_count": len(result["changed"]),
                "timestamp": datetime.now().isoformat(),
            })

        self.state["response_hashes"] = current_hashes
        return result

    def check_certificates(self) -> dict:
        """Check Certificate Transparency logs for new certs."""
        result = {"new_certs": [], "total": 0}

        try:
            resp = requests.get(
                f"https://crt.sh/?q=%.{self.domain}&output=json", timeout=15)
            if resp.status_code == 200:
                certs = resp.json()
                result["total"] = len(certs)

                # Check for certs issued in the last 24 hours
                recent = [c for c in certs if "2026" in str(c.get("not_before", ""))]
                for cert in recent[:10]:
                    result["new_certs"].append({
                        "name": cert.get("name_value"),
                        "issuer": cert.get("issuer_name"),
                        "not_before": cert.get("not_before"),
                    })
        except Exception:
            pass

        if result["new_certs"]:
            self.changes.append({
                "type": "new_certificates",
                "count": len(result["new_certs"]),
                "timestamp": datetime.now().isoformat(),
            })

        return result

    def check_tech_changes(self) -> dict:
        """Detect technology stack changes."""
        result = {"changes": []}

        try:
            resp = requests.get(f"https://{self.domain}", timeout=10, verify=False)
            headers = dict(resp.headers)

            tech_markers = {
                "server": headers.get("Server", ""),
                "x_powered_by": headers.get("X-Powered-By", ""),
                "x_aspnet": headers.get("X-AspNet-Version", ""),
                "x_drupal": headers.get("X-Drupal-Cache", ""),
                "x_framework": headers.get("X-Framework", ""),
            }

            prev_tech = {t["marker"]: t["value"]
                        for t in self.state.get("technologies", [])}

            for marker, value in tech_markers.items():
                if value and prev_tech.get(marker) != value:
                    result["changes"].append({
                        "marker": marker,
                        "old": prev_tech.get(marker, "unknown"),
                        "new": value,
                    })

            self.state["technologies"] = [
                {"marker": k, "value": v}
                for k, v in tech_markers.items() if v]

        except Exception:
            pass

        if result["changes"]:
            self.changes.append({
                "type": "tech_changes",
                "details": result["changes"],
                "timestamp": datetime.now().isoformat(),
            })

        return result

    def run_full_check(self) -> dict:
        """Run all monitoring checks."""
        results = {
            "domain": self.domain,
            "timestamp": datetime.now().isoformat(),
            "subdomains": self.check_subdomains(),
            "endpoints": self.check_endpoints(),
            "certificates": self.check_certificates(),
            "tech_changes": self.check_tech_changes(),
            "total_changes": len(self.changes),
        }

        self._save_state()

        # Save changes report
        if self.changes:
            changes_file = self.data_dir / f"changes_{int(time.time())}.json"
            changes_file.write_text(json.dumps(self.changes, indent=2))

        return results

    def get_priority_targets(self) -> list[dict]:
        """Get priority targets from changes (new = highest priority)."""
        targets = []
        for change in self.changes:
            if change["type"] == "new_subdomains":
                for sub in change["subdomains"]:
                    targets.append({
                        "url": f"https://{sub}",
                        "priority": "CRITICAL",
                        "reason": "New subdomain — uncharted attack surface",
                    })
            elif change["type"] == "endpoint_changes":
                targets.append({
                    "priority": "HIGH",
                    "reason": "Endpoint content changed — possible new feature",
                })
        return targets
