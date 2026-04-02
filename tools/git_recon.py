#!/usr/bin/env python3
"""
git_recon.py — GitHub/GitLab Secret Hunting & Code Analysis

Searches org repos for leaked secrets in commit history, CI configs,
Dockerfiles, and environment files.

Usage:
    python3 git_recon.py --org target_org --token GITHUB_TOKEN
"""
import json
import os
import re
import time
from pathlib import Path

try:
    import requests
except ImportError:
    requests = None

# ── Secret Patterns ────────────────────────────────────────────────────────────

SECRET_PATTERNS = {
    "aws_access_key": {
        "regex": r"(?:AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16}",
        "severity": "CRITICAL",
        "description": "AWS Access Key ID",
    },
    "aws_secret_key": {
        "regex": r"(?:aws_secret_access_key|AWS_SECRET_ACCESS_KEY)\s*[=:]\s*['\"]?([A-Za-z0-9/+=]{40})['\"]?",
        "severity": "CRITICAL",
        "description": "AWS Secret Access Key",
    },
    "github_token": {
        "regex": r"(ghp_[A-Za-z0-9_]{36}|github_pat_[A-Za-z0-9_]{22}_[A-Za-z0-9_]{59})",
        "severity": "CRITICAL",
        "description": "GitHub Personal Access Token",
    },
    "gitlab_token": {
        "regex": r"glpat-[A-Za-z0-9\-_]{20,}",
        "severity": "CRITICAL",
        "description": "GitLab Personal Access Token",
    },
    "google_api_key": {
        "regex": r"AIza[0-9A-Za-z\-_]{35}",
        "severity": "HIGH",
        "description": "Google API Key",
    },
    "slack_token": {
        "regex": r"xox[baprs]-[0-9A-Za-z\-]{10,}",
        "severity": "HIGH",
        "description": "Slack Token",
    },
    "stripe_key": {
        "regex": r"(?:sk|pk)_(?:live|test)_[0-9a-zA-Z]{24,}",
        "severity": "CRITICAL",
        "description": "Stripe API Key",
    },
    "jwt_token": {
        "regex": r"eyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*",
        "severity": "HIGH",
        "description": "JSON Web Token",
    },
    "private_key": {
        "regex": r"-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----",
        "severity": "CRITICAL",
        "description": "Private Key",
    },
    "generic_secret": {
        "regex": r"(?:password|secret|token|api_key|apikey|passwd|pass)\s*[=:]\s*['\"]([^'\"]{8,})['\"]",
        "severity": "HIGH",
        "description": "Generic Secret/Password",
    },
    "database_url": {
        "regex": r"(?:postgres|mysql|mongodb|redis)://[^\s<>'\"]+",
        "severity": "CRITICAL",
        "description": "Database Connection String",
    },
    "sendgrid_key": {
        "regex": r"SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}",
        "severity": "HIGH",
        "description": "SendGrid API Key",
    },
    "twilio_key": {
        "regex": r"SK[0-9a-fA-F]{32}",
        "severity": "HIGH",
        "description": "Twilio API Key",
    },
    "heroku_key": {
        "regex": r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}",
        "severity": "MEDIUM",
        "description": "Heroku API Key (UUID format)",
    },
}

# ── Interesting Files ──────────────────────────────────────────────────────────

INTERESTING_FILES = [
    ".env", ".env.local", ".env.production", ".env.staging",
    ".env.development", ".env.backup", ".env.example",
    "config.yml", "config.yaml", "config.json",
    "credentials.json", "service-account.json",
    "docker-compose.yml", "Dockerfile",
    ".github/workflows/*.yml", ".gitlab-ci.yml",
    "terraform.tfstate", "terraform.tfvars",
    "wp-config.php", "settings.py", "application.properties",
    "appsettings.json", "web.config",
    ".npmrc", ".pypirc", ".m2/settings.xml",
    "id_rsa", "id_ed25519", ".ssh/config",
]


class GitRecon:
    """GitHub/GitLab secret hunter."""

    def __init__(self, token: str = ""):
        self.token = token or os.environ.get("GITHUB_TOKEN", "")
        self.findings = []
        self.session = requests.Session() if requests else None
        if self.token:
            self.session.headers["Authorization"] = f"token {self.token}"
        self.session.headers["Accept"] = "application/vnd.github.v3+json"

    def search_org_repos(self, org: str) -> list[dict]:
        """List all repos for an organization."""
        repos = []
        page = 1
        while True:
            try:
                resp = self.session.get(
                    f"https://api.github.com/orgs/{org}/repos",
                    params={"per_page": 100, "page": page},
                    timeout=15)
                if resp.status_code != 200:
                    break
                batch = resp.json()
                if not batch:
                    break
                repos.extend([{
                    "name": r["name"],
                    "full_name": r["full_name"],
                    "url": r["html_url"],
                    "language": r.get("language"),
                    "default_branch": r.get("default_branch", "main"),
                    "size": r.get("size", 0),
                    "private": r.get("private", False),
                } for r in batch])
                page += 1
            except Exception:
                break
            time.sleep(0.5)

        return repos

    def search_code(self, org: str, query: str = "") -> list[dict]:
        """Search code across org for secrets."""
        results = []
        search_queries = [
            f"org:{org} password",
            f"org:{org} api_key",
            f"org:{org} secret",
            f"org:{org} token",
            f"org:{org} AWS_ACCESS_KEY",
            f"org:{org} PRIVATE KEY",
            f"org:{org} filename:.env",
            f"org:{org} filename:config.yml password",
            f"org:{org} filename:docker-compose.yml",
        ]

        if query:
            search_queries = [f"org:{org} {query}"]

        for sq in search_queries:
            try:
                resp = self.session.get(
                    "https://api.github.com/search/code",
                    params={"q": sq, "per_page": 30},
                    timeout=15)

                if resp.status_code == 200:
                    for item in resp.json().get("items", []):
                        results.append({
                            "repo": item["repository"]["full_name"],
                            "path": item["path"],
                            "url": item["html_url"],
                            "query": sq,
                        })
                elif resp.status_code == 403:
                    # Rate limited
                    time.sleep(30)
            except Exception:
                continue

            time.sleep(2)  # GitHub rate limit

        return results

    def scan_file_contents(self, content: str,
                           filename: str = "") -> list[dict]:
        """Scan file contents for secret patterns."""
        findings = []
        for pattern_name, pattern in SECRET_PATTERNS.items():
            matches = re.finditer(pattern["regex"], content, re.IGNORECASE)
            for match in matches:
                secret = match.group(0)
                # Filter false positives
                if len(secret) < 8:
                    continue
                if all(c == secret[0] for c in secret):
                    continue  # Repeated characters
                if secret in ("password123", "changeme", "example",
                             "your_token_here", "xxx"):
                    continue

                findings.append({
                    "type": pattern_name,
                    "description": pattern["description"],
                    "severity": pattern["severity"],
                    "value": secret[:20] + "..." if len(secret) > 20 else secret,
                    "filename": filename,
                    "line": content[:match.start()].count("\n") + 1,
                })

        return findings

    def scan_repo(self, repo_full_name: str) -> list[dict]:
        """Scan a repository for interesting files and secrets."""
        findings = []

        # Get repo tree
        try:
            resp = self.session.get(
                f"https://api.github.com/repos/{repo_full_name}/git/trees/HEAD",
                params={"recursive": "1"}, timeout=15)
            if resp.status_code != 200:
                return []
            tree = resp.json().get("tree", [])
        except Exception:
            return []

        # Check for interesting files
        for item in tree:
            path = item.get("path", "")
            basename = os.path.basename(path)

            interesting = any(
                basename == f or path.endswith(f.lstrip("*"))
                for f in INTERESTING_FILES)

            if not interesting:
                continue

            # Fetch file content
            try:
                resp = self.session.get(
                    f"https://api.github.com/repos/{repo_full_name}/contents/{path}",
                    timeout=10)
                if resp.status_code == 200:
                    import base64
                    content_b64 = resp.json().get("content", "")
                    if content_b64:
                        content = base64.b64decode(content_b64).decode("utf-8", errors="ignore")
                        file_findings = self.scan_file_contents(content, path)
                        for f in file_findings:
                            f["repo"] = repo_full_name
                            f["file_url"] = resp.json().get("html_url", "")
                        findings.extend(file_findings)
            except Exception:
                continue

            time.sleep(0.5)

        self.findings.extend(findings)
        return findings

    def search_commit_history(self, repo_full_name: str,
                              max_commits: int = 50) -> list[dict]:
        """Search commit messages and diffs for secrets."""
        findings = []

        try:
            resp = self.session.get(
                f"https://api.github.com/repos/{repo_full_name}/commits",
                params={"per_page": max_commits}, timeout=15)
            if resp.status_code != 200:
                return []

            for commit in resp.json():
                msg = commit.get("commit", {}).get("message", "")
                # Check commit messages for secret indicators
                secret_words = ["password", "secret", "key", "credential",
                               "remove secret", "fix leak", "oops"]
                if any(w in msg.lower() for w in secret_words):
                    # Fetch this commit's diff
                    try:
                        diff_resp = self.session.get(
                            commit["url"], timeout=10)
                        if diff_resp.status_code == 200:
                            for file_obj in diff_resp.json().get("files", []):
                                patch = file_obj.get("patch", "")
                                if patch:
                                    file_findings = self.scan_file_contents(
                                        patch, file_obj.get("filename", ""))
                                    for f in file_findings:
                                        f["repo"] = repo_full_name
                                        f["commit"] = commit["sha"][:8]
                                        f["commit_msg"] = msg[:100]
                                        f["commit_url"] = commit["html_url"]
                                    findings.extend(file_findings)
                    except Exception:
                        continue

                time.sleep(0.5)

        except Exception:
            pass

        self.findings.extend(findings)
        return findings

    def run_full_scan(self, org: str) -> dict:
        """Run full GitHub recon on an organization."""
        results = {
            "org": org,
            "repos_found": 0,
            "files_scanned": 0,
            "secrets_found": 0,
            "critical_secrets": 0,
            "findings": [],
        }

        # Get all repos
        repos = self.search_org_repos(org)
        results["repos_found"] = len(repos)

        # Scan each repo (limit to top 20 by size)
        repos_sorted = sorted(repos, key=lambda r: r["size"], reverse=True)[:20]
        for repo in repos_sorted:
            repo_findings = self.scan_repo(repo["full_name"])
            commit_findings = self.search_commit_history(repo["full_name"], 20)
            all_findings = repo_findings + commit_findings

            results["findings"].extend(all_findings)

        # Also run code search
        code_hits = self.search_code(org)
        results["code_search_hits"] = len(code_hits)

        results["secrets_found"] = len(results["findings"])
        results["critical_secrets"] = sum(
            1 for f in results["findings"] if f.get("severity") == "CRITICAL")

        return results

    def save_findings(self, target: str) -> None:
        out_dir = Path(f"findings/{target}/git_recon")
        out_dir.mkdir(parents=True, exist_ok=True)
        if self.findings:
            out_file = out_dir / f"git_secrets_{int(time.time())}.json"
            out_file.write_text(json.dumps(self.findings, indent=2, default=str))
