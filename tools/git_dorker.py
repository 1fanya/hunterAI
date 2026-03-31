#!/usr/bin/env python3
"""
Git Dorker — GitHub/GitLab Secret Discovery

Searches for exposed secrets and sensitive information:
- GitHub code search for target-specific secrets
- .git directory exposure on web servers
- Common sensitive file paths
- GitHub repo enumeration for the target org

Usage:
    python3 git_dorker.py --target target.com
    python3 git_dorker.py --target target.com --org targetcorp
    python3 git_dorker.py --check-git https://target.com
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
from urllib.parse import quote

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


def http_get(url, headers=None, timeout=10):
    """Simple HTTP GET request."""
    default_headers = {"User-Agent": "Mozilla/5.0"}
    if headers:
        default_headers.update(headers)
    try:
        req = Request(url, headers=default_headers)
        with urlopen(req, timeout=timeout) as resp:
            return {"status": resp.status, "body": resp.read().decode("utf-8", errors="replace")}
    except HTTPError as e:
        body = ""
        try:
            body = e.read().decode("utf-8", errors="replace")
        except Exception:
            pass
        return {"status": e.code, "body": body}
    except Exception:
        return {"status": 0, "body": ""}


# GitHub code search dorks
GITHUB_DORKS = [
    # API keys and tokens
    ('"{domain}" password', "Hardcoded password"),
    ('"{domain}" api_key', "API key exposure"),
    ('"{domain}" apikey', "API key exposure"),
    ('"{domain}" secret_key', "Secret key exposure"),
    ('"{domain}" access_token', "Access token"),
    ('"{domain}" private_key', "Private key"),
    ('"{domain}" client_secret', "OAuth client secret"),
    ('"{domain}" aws_access_key', "AWS access key"),
    ('"{domain}" AKIA', "AWS access key ID"),

    # Config files
    ('"{domain}" filename:.env', ".env file"),
    ('"{domain}" filename:config.json', "Config file"),
    ('"{domain}" filename:settings.py', "Django settings"),
    ('"{domain}" filename:database.yml', "Database config"),
    ('"{domain}" filename:credentials', "Credentials file"),
    ('"{domain}" filename:.htpasswd', "htpasswd file"),
    ('"{domain}" filename:wp-config.php', "WordPress config"),

    # Internal URLs
    ('"{domain}" filename:*.sql', "SQL dump"),
    ('"{domain}" internal', "Internal references"),
    ('"{domain}" staging', "Staging environment"),
    ('"{domain}" admin', "Admin references"),

    # Specific secrets
    ('"{domain}" Bearer', "Bearer token"),
    ('"{domain}" authorization', "Authorization header"),
    ('"{domain}" ssh-rsa', "SSH private key"),
    ('org:{org}' + ' filename:.env', "Org .env files"),
    ('org:{org}' + ' password', "Org passwords"),
]

# .git exposure paths
GIT_PATHS = [
    ("/.git/config", "Git config — may reveal repo URL and credentials"),
    ("/.git/HEAD", "Git HEAD — confirms .git exposure"),
    ("/.git/refs/heads/main", "Git branch ref"),
    ("/.git/refs/heads/master", "Git branch ref"),
    ("/.git/logs/HEAD", "Git log — commit history with emails"),
    ("/.git/COMMIT_EDITMSG", "Last commit message"),
    ("/.git/description", "Git description"),
    ("/.git/info/refs", "Git refs"),
    ("/.git/packed-refs", "Git packed refs"),
]

# Sensitive file paths to check on web
SENSITIVE_PATHS = [
    ("/.env", "Environment variables — may contain API keys, DB passwords"),
    ("/.env.local", "Local environment"),
    ("/.env.production", "Production environment"),
    ("/.env.backup", "Environment backup"),
    ("/config.json", "Configuration file"),
    ("/config.yaml", "Configuration file"),
    ("/config.yml", "Configuration file"),
    ("/.aws/credentials", "AWS credentials"),
    ("/backup.sql", "SQL backup"),
    ("/dump.sql", "SQL dump"),
    ("/database.sql", "Database dump"),
    ("/.DS_Store", "macOS directory listing"),
    ("/robots.txt", "Robots.txt — reveals hidden paths"),
    ("/sitemap.xml", "Sitemap"),
    ("/.well-known/security.txt", "Security policy"),
    ("/crossdomain.xml", "Flash crossdomain policy"),
    ("/server-status", "Apache server status"),
    ("/phpinfo.php", "PHP info page"),
    ("/.svn/entries", "SVN directory"),
    ("/.hg/dirstate", "Mercurial directory"),
    ("/WEB-INF/web.xml", "Java web config"),
    ("/web.config", "IIS config"),
    ("/package.json", "NPM package — reveals dependencies"),
    ("/composer.json", "PHP dependencies"),
    ("/Gemfile", "Ruby dependencies"),
]


class GitDorker:
    """GitHub dorking and exposed git/secrets detection."""

    def __init__(self, target, org=None, github_token=None, rate_limit=2.0):
        self.target = target
        self.org = org or target.split(".")[0]
        self.github_token = github_token or os.environ.get("GITHUB_TOKEN", "")
        self.rate_limit = rate_limit
        self.findings = []

    def _sleep(self):
        if self.rate_limit > 0:
            time.sleep(1.0 / self.rate_limit)

    def _add_finding(self, category, severity, details, url=None):
        finding = {
            "category": category,
            "severity": severity,
            "details": details,
            "url": url,
            "found_at": datetime.now().isoformat(),
        }
        self.findings.append(finding)
        log("vuln", f"[{severity}] {category}: {details[:80]}")

    def check_git_exposure(self, base_url=None):
        """Check for .git directory exposure on the web server."""
        if not base_url:
            base_url = f"https://{self.target}"
        base_url = base_url.rstrip("/")

        log("info", f"Checking .git exposure on {base_url}...")

        for path, desc in GIT_PATHS:
            url = f"{base_url}{path}"
            resp = http_get(url)
            self._sleep()

            if resp["status"] == 200 and resp["body"]:
                body = resp["body"]
                # Verify it's actual git content
                if path == "/.git/config" and ("[core]" in body or "[remote" in body):
                    self._add_finding(
                        "GIT_EXPOSED", "HIGH",
                        f".git/config exposed — {desc}. May contain repo URLs and credentials.",
                        url=url,
                    )
                elif path == "/.git/HEAD" and ("ref:" in body or len(body) == 40):
                    self._add_finding(
                        "GIT_EXPOSED", "HIGH",
                        f".git/HEAD exposed — entire git history downloadable. "
                        f"Use git-dumper to extract source code.",
                        url=url,
                    )
                elif path == "/.git/logs/HEAD" and ("commit" in body.lower() or "@" in body):
                    self._add_finding(
                        "GIT_LOG_EXPOSED", "MEDIUM",
                        f"Git logs exposed — commit history with author emails visible.",
                        url=url,
                    )

    def check_sensitive_files(self, base_url=None):
        """Check for exposed sensitive files on the web server."""
        if not base_url:
            base_url = f"https://{self.target}"
        base_url = base_url.rstrip("/")

        log("info", f"Checking sensitive files on {base_url}...")

        for path, desc in SENSITIVE_PATHS:
            url = f"{base_url}{path}"
            resp = http_get(url)
            self._sleep()

            if resp["status"] == 200 and resp["body"]:
                body = resp["body"]
                size = len(body)

                # Validate it's not just a custom 404 page
                if size > 20 and size < 500000:
                    # Look for specific indicators based on file type
                    is_real = False

                    if ".env" in path and ("=" in body and any(
                        kw in body.upper() for kw in ["DB_", "API_", "SECRET", "KEY", "PASSWORD", "TOKEN"]
                    )):
                        is_real = True
                        severity = "CRITICAL"
                    elif ".sql" in path and any(
                        kw in body.upper() for kw in ["CREATE TABLE", "INSERT INTO", "SELECT"]
                    ):
                        is_real = True
                        severity = "CRITICAL"
                    elif "config" in path and any(
                        kw in body.lower() for kw in ["password", "secret", "key", "token", "database"]
                    ):
                        is_real = True
                        severity = "HIGH"
                    elif path == "/robots.txt" and ("Disallow" in body or "Allow" in body):
                        is_real = True
                        severity = "LOW"
                        # Extract disallowed paths
                        hidden = re.findall(r'Disallow:\s*(\S+)', body)
                        if hidden:
                            desc += f" Hidden paths: {', '.join(hidden[:5])}"
                    elif path in ("/phpinfo.php", "/server-status"):
                        is_real = True
                        severity = "MEDIUM"
                    elif "package.json" in path and '"name"' in body:
                        is_real = True
                        severity = "LOW"

                    if is_real:
                        self._add_finding(
                            "SENSITIVE_FILE", severity,
                            f"{path} exposed ({size}B) — {desc}",
                            url=url,
                        )

    def github_search(self):
        """Search GitHub for target-related secrets (requires GITHUB_TOKEN)."""
        if not self.github_token:
            log("warn", "No GITHUB_TOKEN set — skipping GitHub code search")
            log("info", "Set GITHUB_TOKEN env var for GitHub dorking")
            return

        log("info", f"GitHub dorking for {self.target}...")

        for dork_template, desc in GITHUB_DORKS[:15]:  # Limit to avoid rate limits
            dork = dork_template.replace("{domain}", self.target).replace("{org}", self.org)
            encoded = quote(dork)
            url = f"https://api.github.com/search/code?q={encoded}&per_page=5"

            resp = http_get(url, headers={"Authorization": f"token {self.github_token}"})
            self._sleep()
            time.sleep(2)  # Extra delay for GitHub rate limits

            if resp["status"] == 200:
                try:
                    data = json.loads(resp["body"])
                    total = data.get("total_count", 0)
                    if total > 0:
                        items = data.get("items", [])
                        repos = set()
                        for item in items:
                            repo = item.get("repository", {}).get("full_name", "")
                            if repo:
                                repos.add(repo)

                        self._add_finding(
                            "GITHUB_LEAK", "MEDIUM",
                            f"GitHub: '{dork[:50]}' → {total} results in {len(repos)} repos. "
                            f"{desc}. Repos: {', '.join(list(repos)[:3])}",
                            url=f"https://github.com/search?q={encoded}&type=code",
                        )
                except json.JSONDecodeError:
                    pass
            elif resp["status"] == 403:
                log("warn", "GitHub rate limit hit — pausing 30s")
                time.sleep(30)

    def run_all(self):
        """Run all checks."""
        self.check_git_exposure()
        self.check_sensitive_files()
        self.github_search()
        return self.findings

    def save_findings(self, target_name):
        if not self.findings:
            return
        output_dir = os.path.join(FINDINGS_DIR, target_name)
        os.makedirs(output_dir, exist_ok=True)
        filepath = os.path.join(output_dir, "git_findings.json")
        with open(filepath, "w") as f:
            json.dump({"findings": self.findings}, f, indent=2)
        log("ok", f"Saved {len(self.findings)} findings to {filepath}")

    def print_summary(self):
        print(f"\n{BOLD}{'='*60}{NC}")
        print(f"{BOLD}  Git/Secret Exposure Summary{NC}")
        print(f"{'='*60}\n")
        if self.findings:
            for f in self.findings:
                color = RED if f["severity"] in ("CRITICAL", "HIGH") else YELLOW
                print(f"  {color}[{f['severity']}] {f['category']}{NC}")
                print(f"    {f['details'][:100]}")
                if f.get("url"):
                    print(f"    URL: {f['url']}")
        else:
            print(f"  {GREEN}No exposed secrets found ✓{NC}")
        print()


def main():
    parser = argparse.ArgumentParser(description="Git & Secret Dorker")
    parser.add_argument("--target", required=True, help="Target domain")
    parser.add_argument("--org", help="GitHub organization name")
    parser.add_argument("--check-git", help="Check specific URL for .git exposure")
    parser.add_argument("--rate-limit", type=float, default=2.0)
    args = parser.parse_args()

    dorker = GitDorker(args.target, org=args.org, rate_limit=args.rate_limit)

    if args.check_git:
        dorker.check_git_exposure(args.check_git)
    else:
        dorker.run_all()

    dorker.print_summary()
    dorker.save_findings(args.target)


if __name__ == "__main__":
    main()
