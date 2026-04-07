#!/usr/bin/env python3
"""
recon_cron.py — Continuous Recon & Change Monitor

Background monitoring for new subdomains, certificate changes,
and attack surface drift. Alerts via Telegram when changes detected.

Usage:
    from recon_cron import ReconCron
    cron = ReconCron(["target.com", "app.target.com"])
    cron.run_once()   # Single check
    cron.run_loop()   # Continuous monitoring (every hour)
"""
import json
import os
import subprocess
import time
from pathlib import Path

try:
    import requests
except ImportError:
    requests = None


class ReconCron:
    """Continuous subdomain and attack surface monitor."""

    def __init__(self, domains: list = None,
                 state_dir: str = "hunt-memory/recon_monitor"):
        self.domains = domains or []
        self.state_dir = Path(state_dir)
        self.state_dir.mkdir(parents=True, exist_ok=True)
        self.session = requests.Session() if requests else None
        self.notifier = self._init_notifier()

    def _init_notifier(self):
        """Try to load Telegram notifier."""
        try:
            from telegram_notifier import TelegramNotifier
            n = TelegramNotifier()
            return n if n.enabled else None
        except ImportError:
            return None

    def _load_state(self, domain: str) -> dict:
        """Load previous state for a domain."""
        state_file = self.state_dir / f"{domain}.json"
        if state_file.exists():
            try:
                return json.loads(state_file.read_text(encoding="utf-8"))
            except Exception:
                pass
        return {"subdomains": [], "ports": {}, "last_check": None}

    def _save_state(self, domain: str, state: dict):
        """Save current state."""
        state["last_check"] = time.strftime("%Y-%m-%d %H:%M:%S")
        (self.state_dir / f"{domain}.json").write_text(
            json.dumps(state, indent=2), encoding="utf-8")

    def _alert(self, message: str):
        """Send alert via Telegram."""
        if self.notifier:
            self.notifier.send(message)

    def check_subdomains(self, domain: str) -> dict:
        """Check for new subdomains using subfinder + crt.sh."""
        current = set()

        # subfinder
        try:
            result = subprocess.run(
                ["subfinder", "-d", domain, "-silent"],
                capture_output=True, text=True, timeout=120)
            for line in result.stdout.strip().split("\n"):
                if line.strip():
                    current.add(line.strip().lower())
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass

        # crt.sh
        if self.session:
            try:
                resp = self.session.get(
                    f"https://crt.sh/?q=%25.{domain}&output=json",
                    timeout=30)
                if resp.status_code == 200:
                    for cert in resp.json():
                        for name in cert.get("name_value", "").split("\n"):
                            name = name.strip().lower()
                            if name.endswith(domain) and "*" not in name:
                                current.add(name)
            except Exception:
                pass

        # Compare with previous
        prev_state = self._load_state(domain)
        previous = set(prev_state.get("subdomains", []))
        new_subs = current - previous
        removed = previous - current

        # Save new state
        prev_state["subdomains"] = sorted(current)
        self._save_state(domain, prev_state)

        return {
            "domain": domain,
            "total": len(current),
            "new": sorted(new_subs),
            "removed": sorted(removed),
        }

    def check_live_status(self, domain: str) -> dict:
        """Check live status of domain and subdomains with httpx."""
        state = self._load_state(domain)
        subs = state.get("subdomains", [domain])[:50]

        live = []
        try:
            proc = subprocess.run(
                ["httpx", "-silent", "-status-code", "-title", "-tech-detect"],
                input="\n".join(subs),
                capture_output=True, text=True, timeout=120)
            for line in proc.stdout.strip().split("\n"):
                if line.strip():
                    live.append(line.strip())
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass

        return {"domain": domain, "live_hosts": live, "count": len(live)}

    def run_once(self) -> dict:
        """Run a single check for all domains."""
        results = {"timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
                    "domains": {}}

        for domain in self.domains:
            sub_result = self.check_subdomains(domain)
            results["domains"][domain] = sub_result

            # Alert on new subdomains
            if sub_result["new"]:
                msg = (f"🆕 <b>New Subdomains: {domain}</b>\n"
                       f"Found {len(sub_result['new'])} new:\n")
                for s in sub_result["new"][:10]:
                    msg += f"  • {s}\n"
                if len(sub_result["new"]) > 10:
                    msg += f"  ...and {len(sub_result['new']) - 10} more"
                self._alert(msg)

        return results

    def run_loop(self, interval: int = 3600):
        """Continuous monitoring loop."""
        self._alert(f"🔄 Recon monitor started for {len(self.domains)} domains")
        while True:
            try:
                results = self.run_once()
                total_new = sum(len(d.get("new", []))
                               for d in results["domains"].values())
                if total_new > 0:
                    # Save detailed report
                    (self.state_dir / f"report_{int(time.time())}.json").write_text(
                        json.dumps(results, indent=2), encoding="utf-8")
            except Exception as e:
                self._alert(f"❌ Recon monitor error: {str(e)[:200]}")
            time.sleep(interval)

    def add_domain(self, domain: str):
        """Add domain to monitor list."""
        if domain not in self.domains:
            self.domains.append(domain)

    def get_history(self, domain: str) -> list:
        """Get monitoring history for a domain."""
        reports = []
        for f in sorted(self.state_dir.glob("report_*.json")):
            try:
                data = json.loads(f.read_text(encoding="utf-8"))
                if domain in data.get("domains", {}):
                    reports.append(data)
            except Exception:
                continue
        return reports
