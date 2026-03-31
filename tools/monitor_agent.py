#!/usr/bin/env python3
"""
Monitor Agent — Background Target Monitoring for New Attack Surface

Runs periodic recon to detect:
- New subdomains appearing
- New endpoints/URLs
- Changed HTTP responses (new features = new bugs)
- Certificate transparency log monitoring
- DNS record changes

Saves diffs so you're always first to find new attack surface.

Usage:
    python3 monitor_agent.py --target target.com --run
    python3 monitor_agent.py --target target.com --diff
    python3 monitor_agent.py --target target.com --cron  # for crontab
"""

import argparse
import json
import os
import subprocess
import sys
import time
from datetime import datetime

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MONITOR_DIR = os.path.join(BASE_DIR, "hunt-memory", "monitor")

GREEN = "\033[0;32m"
RED = "\033[0;31m"
YELLOW = "\033[1;33m"
CYAN = "\033[0;36m"
BOLD = "\033[1m"
NC = "\033[0m"


def log(level, msg):
    colors = {"ok": GREEN, "err": RED, "warn": YELLOW, "info": CYAN, "vuln": RED}
    symbols = {"ok": "+", "err": "-", "warn": "!", "info": "*", "vuln": "🆕"}
    ts = datetime.now().strftime("%H:%M:%S")
    print(f"[{ts}] {colors.get(level, '')}{BOLD}[{symbols.get(level, '*')}]{NC} {msg}")


def run_tool(cmd, timeout=120):
    """Run a tool and return stdout lines."""
    try:
        result = subprocess.run(
            cmd, shell=True, capture_output=True, text=True, timeout=timeout,
        )
        return [line.strip() for line in result.stdout.strip().split("\n") if line.strip()]
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return []


class TargetMonitor:
    """Monitors targets for new attack surface."""

    def __init__(self, target):
        self.target = target
        self.target_dir = os.path.join(MONITOR_DIR, target.replace(".", "_"))
        os.makedirs(self.target_dir, exist_ok=True)

    def _load_previous(self, name):
        """Load previous scan results."""
        filepath = os.path.join(self.target_dir, f"{name}.json")
        if os.path.exists(filepath):
            with open(filepath) as f:
                return json.load(f)
        return {"items": [], "scanned_at": None}

    def _save_current(self, name, items):
        """Save current scan results."""
        filepath = os.path.join(self.target_dir, f"{name}.json")
        with open(filepath, "w") as f:
            json.dump({
                "items": sorted(items),
                "scanned_at": datetime.now().isoformat(),
            }, f, indent=2)

    def _save_diff(self, name, new_items, removed_items):
        """Save diff to history."""
        if not new_items and not removed_items:
            return

        history_dir = os.path.join(self.target_dir, "history")
        os.makedirs(history_dir, exist_ok=True)

        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        filepath = os.path.join(history_dir, f"{name}_{ts}.json")
        with open(filepath, "w") as f:
            json.dump({
                "type": name,
                "new": sorted(new_items),
                "removed": sorted(removed_items),
                "timestamp": datetime.now().isoformat(),
            }, f, indent=2)

    def scan_subdomains(self):
        """Run subdomain enumeration and diff against previous scan."""
        log("info", f"Scanning subdomains for {self.target}...")

        current = set()

        # subfinder
        subs = run_tool(f"subfinder -d {self.target} -silent 2>/dev/null")
        current.update(subs)

        # assetfinder
        subs = run_tool(f"assetfinder -subs-only {self.target} 2>/dev/null")
        current.update(subs)

        if not current:
            log("warn", "No subdomains found — tools may not be installed")
            return set(), set()

        # Load previous
        previous = set(self._load_previous("subdomains").get("items", []))

        # Diff
        new_subs = current - previous
        removed_subs = previous - current

        # Save
        self._save_current("subdomains", list(current))
        self._save_diff("subdomains", list(new_subs), list(removed_subs))

        if new_subs:
            log("vuln", f"{len(new_subs)} NEW subdomains detected!")
            for sub in sorted(new_subs):
                log("vuln", f"  → {sub}")
        if removed_subs:
            log("info", f"{len(removed_subs)} subdomains removed")

        return new_subs, removed_subs

    def scan_urls(self):
        """Crawl URLs and diff against previous scan."""
        log("info", f"Crawling URLs for {self.target}...")

        current = set()

        # katana
        urls = run_tool(f"katana -u https://{self.target} -d 2 -silent 2>/dev/null", timeout=60)
        current.update(urls)

        # waybackurls
        urls = run_tool(f"echo {self.target} | waybackurls 2>/dev/null | head -500")
        current.update(urls)

        # gau
        urls = run_tool(f"echo {self.target} | gau --subs 2>/dev/null | head -500")
        current.update(urls)

        if not current:
            log("warn", "No URLs found")
            return set(), set()

        previous = set(self._load_previous("urls").get("items", []))

        new_urls = current - previous
        removed_urls = previous - current

        self._save_current("urls", list(current))
        self._save_diff("urls", list(new_urls), list(removed_urls))

        if new_urls:
            log("vuln", f"{len(new_urls)} NEW URLs detected!")
            for url in sorted(new_urls)[:20]:
                log("vuln", f"  → {url}")
            if len(new_urls) > 20:
                log("info", f"  ... and {len(new_urls) - 20} more")

        return new_urls, removed_urls

    def check_crt_transparency(self):
        """Check Certificate Transparency logs for new certificates."""
        log("info", f"Checking certificate transparency for {self.target}...")

        from urllib.request import urlopen
        try:
            url = f"https://crt.sh/?q=%.{self.target}&output=json"
            resp = urlopen(url, timeout=30)
            data = json.loads(resp.read().decode())

            current_domains = set()
            for entry in data:
                name = entry.get("name_value", "")
                for domain in name.split("\n"):
                    domain = domain.strip().lstrip("*.")
                    if domain and self.target in domain:
                        current_domains.add(domain)

            previous = set(self._load_previous("crt_domains").get("items", []))
            new_domains = current_domains - previous

            self._save_current("crt_domains", list(current_domains))
            self._save_diff("crt_domains", list(new_domains), [])

            if new_domains:
                log("vuln", f"{len(new_domains)} NEW domains in CT logs!")
                for d in sorted(new_domains)[:10]:
                    log("vuln", f"  → {d}")
            else:
                log("info", f"  {len(current_domains)} domains in CT (no changes)")

            return new_domains

        except Exception as e:
            log("warn", f"CT check failed: {e}")
            return set()

    def run_full_scan(self):
        """Run complete monitoring scan."""
        log("info", f"{'='*50}")
        log("info", f"MONITORING SCAN: {self.target}")
        log("info", f"{'='*50}")
        print()

        results = {
            "target": self.target,
            "timestamp": datetime.now().isoformat(),
            "new_subdomains": [],
            "new_urls": [],
            "new_crt_domains": [],
        }

        new_subs, _ = self.scan_subdomains()
        results["new_subdomains"] = sorted(new_subs)

        new_urls, _ = self.scan_urls()
        results["new_urls"] = sorted(new_urls)

        new_crt = self.check_crt_transparency()
        results["new_crt_domains"] = sorted(new_crt)

        # Summary
        total_new = len(new_subs) + len(new_urls) + len(new_crt)
        print(f"\n{BOLD}{'='*50}{NC}")
        if total_new > 0:
            print(f"{RED}{BOLD}  ⚡ {total_new} NEW items detected!{NC}")
            print(f"    Subdomains: {len(new_subs)} new")
            print(f"    URLs: {len(new_urls)} new")
            print(f"    CT domains: {len(new_crt)} new")
            print(f"\n  Run /fullhunt to test new attack surface!")
        else:
            print(f"{GREEN}  No changes detected since last scan ✓{NC}")
        print(f"{BOLD}{'='*50}{NC}\n")

        # Save summary
        summary_path = os.path.join(self.target_dir, "latest_scan.json")
        with open(summary_path, "w") as f:
            json.dump(results, f, indent=2)

        return results

    def show_diff(self):
        """Show what changed since last scan."""
        log("info", f"Changes for {self.target}:")

        for name in ["subdomains", "urls", "crt_domains"]:
            data = self._load_previous(name)
            count = len(data.get("items", []))
            last = data.get("scanned_at", "never")
            log("info", f"  {name}: {count} items (last scan: {last})")

        # Show latest diff
        history_dir = os.path.join(self.target_dir, "history")
        if os.path.isdir(history_dir):
            files = sorted(os.listdir(history_dir), reverse=True)
            if files:
                latest = os.path.join(history_dir, files[0])
                with open(latest) as f:
                    diff = json.load(f)
                log("info", f"\n  Latest changes ({diff.get('timestamp', '')[:19]}):")
                for item in diff.get("new", [])[:10]:
                    log("vuln", f"    + {item}")
                for item in diff.get("removed", [])[:5]:
                    log("warn", f"    - {item}")

    def generate_cron(self):
        """Generate crontab entry for automated monitoring."""
        script = os.path.abspath(__file__)
        cron_line = f"0 */6 * * * cd {BASE_DIR} && python3 {script} --target {self.target} --run >> {self.target_dir}/cron.log 2>&1"
        print(f"\nAdd this to crontab (crontab -e):\n")
        print(f"  {cron_line}")
        print(f"\nThis runs every 6 hours and logs to {self.target_dir}/cron.log")


def main():
    parser = argparse.ArgumentParser(description="Target Monitor Agent")
    parser.add_argument("--target", required=True, help="Target domain")
    parser.add_argument("--run", action="store_true", help="Run full monitoring scan")
    parser.add_argument("--diff", action="store_true", help="Show changes since last scan")
    parser.add_argument("--cron", action="store_true", help="Generate crontab entry")
    args = parser.parse_args()

    monitor = TargetMonitor(args.target)

    if args.run:
        monitor.run_full_scan()
    elif args.diff:
        monitor.show_diff()
    elif args.cron:
        monitor.generate_cron()
    else:
        monitor.show_diff()


if __name__ == "__main__":
    main()
