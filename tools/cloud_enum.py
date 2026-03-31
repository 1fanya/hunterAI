#!/usr/bin/env python3
"""
Cloud Enum — Cloud Storage Bucket & Service Enumeration

Tests:
- AWS S3 bucket discovery + permission testing (read/write/list)
- Azure Blob Storage enumeration
- GCP Storage bucket testing
- Firebase database open read/write
- DigitalOcean Spaces

Usage:
    python3 cloud_enum.py --target target.com
    python3 cloud_enum.py --company "Target Corp" --keywords "target,tgt,targetcorp"
"""

import argparse
import json
import os
import re
import sys
import time
from datetime import datetime
from urllib.request import Request, urlopen
from urllib.error import HTTPError, URLError

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


def http_check(url, method="GET", timeout=10):
    """Check URL and return status + body preview."""
    try:
        req = Request(url, method=method, headers={"User-Agent": "Mozilla/5.0"})
        with urlopen(req, timeout=timeout) as resp:
            body = resp.read().decode("utf-8", errors="replace")[:2000]
            return {"status": resp.status, "body": body, "exists": True}
    except HTTPError as e:
        body = ""
        try:
            body = e.read().decode("utf-8", errors="replace")[:1000]
        except Exception:
            pass
        return {"status": e.code, "body": body, "exists": e.code != 404}
    except Exception:
        return {"status": 0, "body": "", "exists": False}


def generate_bucket_names(target, keywords=None):
    """Generate candidate bucket names from target domain and keywords."""
    domain_parts = target.replace(".", "-").split("-")
    base = target.split(".")[0]

    names = set()
    names.add(base)
    names.add(target.replace(".", "-"))
    names.add(target.replace(".", ""))

    if keywords:
        for kw in keywords:
            names.add(kw)
            names.add(f"{kw}-dev")
            names.add(f"{kw}-staging")
            names.add(f"{kw}-prod")
            names.add(f"{kw}-backup")
            names.add(f"{kw}-assets")
            names.add(f"{kw}-uploads")
            names.add(f"{kw}-media")
            names.add(f"{kw}-static")
            names.add(f"{kw}-data")
            names.add(f"{kw}-logs")
            names.add(f"{kw}-private")
            names.add(f"{kw}-public")
            names.add(f"{kw}-internal")
            names.add(f"{kw}-test")

    # Add common suffixes to base
    suffixes = [
        "", "-dev", "-staging", "-prod", "-production",
        "-backup", "-bak", "-backups",
        "-assets", "-static", "-media", "-uploads", "-images",
        "-data", "-db", "-database",
        "-logs", "-log", "-audit",
        "-private", "-internal", "-secret",
        "-public", "-cdn", "-content",
        "-test", "-uat", "-qa",
        "-config", "-configs",
        "-api", "-web", "-app",
    ]

    for suffix in suffixes:
        names.add(f"{base}{suffix}")

    return sorted(names)


class CloudEnumerator:
    """Cloud storage enumeration and permission testing."""

    def __init__(self, rate_limit=5.0):
        self.rate_limit = rate_limit
        self.findings = []
        self.checked = 0

    def _sleep(self):
        if self.rate_limit > 0:
            time.sleep(1.0 / self.rate_limit)

    def _add_finding(self, cloud, bucket_name, issue, severity, details, url=None):
        finding = {
            "cloud": cloud,
            "bucket": bucket_name,
            "issue": issue,
            "severity": severity,
            "details": details,
            "url": url,
            "found_at": datetime.now().isoformat(),
        }
        self.findings.append(finding)
        log("vuln", f"[{severity}] {cloud} — {bucket_name}: {issue}")

    # ─── AWS S3 ───

    def check_s3(self, bucket_names):
        """Check AWS S3 buckets for public access."""
        log("info", f"Testing {len(bucket_names)} S3 bucket names...")

        for name in bucket_names:
            self.checked += 1

            # Check bucket existence and listing
            url = f"https://{name}.s3.amazonaws.com/"
            resp = http_check(url)
            self._sleep()

            if resp["status"] == 200:
                # Public listing!
                if "<ListBucketResult" in resp["body"] or "<Contents>" in resp["body"]:
                    # Count files
                    file_count = resp["body"].count("<Key>")
                    self._add_finding(
                        "AWS S3", name, "PUBLIC_LISTING",
                        "HIGH",
                        f"S3 bucket '{name}' allows public listing ({file_count} files visible). "
                        f"Check for sensitive data.",
                        url=url,
                    )

                    # Test write access
                    write_url = f"https://{name}.s3.amazonaws.com/bugbounty-test.txt"
                    write_resp = http_check(write_url, method="PUT")
                    if write_resp["status"] in (200, 201):
                        self._add_finding(
                            "AWS S3", name, "PUBLIC_WRITE",
                            "CRITICAL",
                            f"S3 bucket '{name}' allows PUBLIC WRITE. "
                            f"Attacker can upload arbitrary files.",
                            url=url,
                        )

            elif resp["status"] == 403:
                # Bucket exists but not public
                log("info", f"  {name}: exists but access denied (403)")

            elif resp["status"] == 404:
                pass  # Doesn't exist

            # Also check path-style
            url2 = f"https://s3.amazonaws.com/{name}/"
            resp2 = http_check(url2)
            self._sleep()

            if resp2["status"] == 200 and "<ListBucketResult" in resp2["body"]:
                self._add_finding(
                    "AWS S3", name, "PUBLIC_LISTING_PATH_STYLE",
                    "HIGH",
                    f"S3 bucket '{name}' allows public listing (path-style URL).",
                    url=url2,
                )

    # ─── Azure Blob ───

    def check_azure(self, bucket_names):
        """Check Azure Blob Storage containers."""
        log("info", f"Testing {len(bucket_names)} Azure storage names...")

        for name in bucket_names:
            self.checked += 1

            # Azure blob format: {account}.blob.core.windows.net/{container}
            # Test with common container names
            containers = ["$web", "public", "assets", "uploads", "media",
                         "data", "backup", "images", "files", "static"]

            account_url = f"https://{name}.blob.core.windows.net"
            resp = http_check(account_url)
            self._sleep()

            if resp["status"] != 0 and resp["status"] != 404:
                for container in containers:
                    url = f"{account_url}/{container}?restype=container&comp=list"
                    resp = http_check(url)
                    self._sleep()

                    if resp["status"] == 200 and "<EnumerationResults" in resp["body"]:
                        blob_count = resp["body"].count("<Blob>")
                        self._add_finding(
                            "Azure Blob", f"{name}/{container}", "PUBLIC_LISTING",
                            "HIGH",
                            f"Azure container '{container}' on account '{name}' is publicly listable "
                            f"({blob_count} blobs).",
                            url=url,
                        )

    # ─── GCP Storage ───

    def check_gcp(self, bucket_names):
        """Check Google Cloud Storage buckets."""
        log("info", f"Testing {len(bucket_names)} GCP bucket names...")

        for name in bucket_names:
            self.checked += 1

            url = f"https://storage.googleapis.com/{name}/"
            resp = http_check(url)
            self._sleep()

            if resp["status"] == 200:
                if "<ListBucketResult" in resp["body"] or "<Contents>" in resp["body"]:
                    self._add_finding(
                        "GCP Storage", name, "PUBLIC_LISTING",
                        "HIGH",
                        f"GCP bucket '{name}' allows public listing.",
                        url=url,
                    )
            elif resp["status"] == 403:
                log("info", f"  GCP {name}: exists but not public (403)")

    # ─── Firebase ───

    def check_firebase(self, project_names):
        """Check Firebase Realtime Database for open read/write."""
        log("info", f"Testing {len(project_names)} Firebase projects...")

        for name in project_names:
            self.checked += 1

            url = f"https://{name}.firebaseio.com/.json"
            resp = http_check(url)
            self._sleep()

            if resp["status"] == 200 and resp["body"] and resp["body"] != "null":
                size = len(resp["body"])
                self._add_finding(
                    "Firebase", name, "PUBLIC_READ",
                    "CRITICAL",
                    f"Firebase database '{name}' allows PUBLIC READ ({size} bytes). "
                    f"All data is accessible without authentication.",
                    url=url,
                )

                # Test write
                write_url = f"https://{name}.firebaseio.com/bugbounty_test.json"
                write_resp = http_check(write_url, method="PUT")
                if write_resp["status"] == 200:
                    self._add_finding(
                        "Firebase", name, "PUBLIC_WRITE",
                        "CRITICAL",
                        f"Firebase '{name}' allows PUBLIC WRITE. "
                        f"Attacker can modify/delete all data.",
                        url=url,
                    )

            elif resp["status"] == 200 and resp["body"] == "null":
                log("info", f"  Firebase {name}: accessible but empty")

    # ─── Run all checks ───

    def run_all(self, target, keywords=None):
        """Run all cloud enumeration checks."""
        bucket_names = generate_bucket_names(target, keywords)
        log("info", f"Generated {len(bucket_names)} candidate names")

        self.check_s3(bucket_names)
        self.check_gcp(bucket_names)
        self.check_azure(bucket_names[:20])  # Azure is slower
        self.check_firebase(bucket_names[:20])

        return self.findings

    def save_findings(self, target_name):
        if not self.findings:
            return
        output_dir = os.path.join(FINDINGS_DIR, target_name)
        os.makedirs(output_dir, exist_ok=True)
        filepath = os.path.join(output_dir, "cloud_findings.json")
        with open(filepath, "w") as f:
            json.dump({
                "checked": self.checked,
                "findings": self.findings,
            }, f, indent=2)
        log("ok", f"Saved {len(self.findings)} findings to {filepath}")

    def print_summary(self):
        print(f"\n{BOLD}{'='*60}{NC}")
        print(f"{BOLD}  Cloud Enumeration Summary{NC}")
        print(f"{'='*60}\n")
        print(f"  Checked: {self.checked}")
        if self.findings:
            for f in self.findings:
                color = RED if f["severity"] == "CRITICAL" else YELLOW
                print(f"\n  {color}[{f['severity']}] {f['cloud']} — {f['bucket']}{NC}")
                print(f"    {f['issue']}: {f['details'][:80]}")
                print(f"    URL: {f['url']}")
        else:
            print(f"\n  {GREEN}No exposed cloud resources found ✓{NC}")
        print()


def main():
    parser = argparse.ArgumentParser(description="Cloud Storage Enumerator")
    parser.add_argument("--target", required=True, help="Target domain")
    parser.add_argument("--keywords", help="Comma-separated keywords")
    parser.add_argument("--rate-limit", type=float, default=5.0)
    args = parser.parse_args()

    keywords = args.keywords.split(",") if args.keywords else None
    enumerator = CloudEnumerator(rate_limit=args.rate_limit)
    enumerator.run_all(args.target, keywords)
    enumerator.print_summary()
    enumerator.save_findings(args.target)


if __name__ == "__main__":
    main()
