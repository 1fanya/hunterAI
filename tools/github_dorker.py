#!/usr/bin/env python3
"""
github_dorker.py — GitHub Code Search for Leaked Secrets & Endpoints

Searches GitHub for leaked API keys, .env files, internal endpoints,
debug configs, and credentials tied to a target domain.

Usage:
    from github_dorker import GitHubDorker
    dorker = GitHubDorker()
    results = dorker.dork("target.com")
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

GITHUB_API = "https://api.github.com"


class GitHubDorker:
    """GitHub code search for bug bounty recon."""

    # High-value dork patterns per category
    DORK_TEMPLATES = {
        "secrets": [
            '"{domain}" password',
            '"{domain}" secret',
            '"{domain}" api_key',
            '"{domain}" apikey',
            '"{domain}" token',
            '"{domain}" client_secret',
            '"{domain}" aws_access_key',
            '"{domain}" private_key',
        ],
        "config_files": [
            '"{domain}" filename:.env',
            '"{domain}" filename:.env.production',
            '"{domain}" filename:config.json',
            '"{domain}" filename:settings.py',
            '"{domain}" filename:application.yml',
            '"{domain}" filename:database.yml',
            '"{domain}" filename:docker-compose.yml',
            '"{domain}" filename:.htaccess',
            '"{domain}" filename:wp-config.php',
        ],
        "endpoints": [
            '"{domain}" filename:swagger.json',
            '"{domain}" filename:openapi.json',
            '"{domain}" /api/v1',
            '"{domain}" /api/internal',
            '"{domain}" /graphql',
            '"{domain}" /admin',
            '"{domain}" /debug',
        ],
        "credentials": [
            '"{domain}" username password',
            '"{domain}" login credentials',
            '"{domain}" jdbc:mysql',
            '"{domain}" mongodb://',
            '"{domain}" redis://',
            '"{domain}" smtp',
        ],
        "cloud": [
            '"{domain}" s3.amazonaws.com',
            '"{domain}" storage.googleapis.com',
            '"{domain}" blob.core.windows.net',
            '"{domain}" firebase',
        ],
    }

    def __init__(self, token: str = ""):
        self.token = token or os.environ.get("GITHUB_TOKEN", "")
        self.session = requests.Session() if requests else None
        if self.session:
            self.session.headers["Accept"] = "application/vnd.github.v3+json"
            self.session.headers["User-Agent"] = "HunterAI/1.0"
            if self.token:
                self.session.headers["Authorization"] = f"token {self.token}"
        self.findings = []

    def search_code(self, query: str, max_results: int = 10) -> list:
        """Search GitHub code with rate limiting."""
        if not self.session:
            return []
        try:
            resp = self.session.get(f"{GITHUB_API}/search/code",
                                    params={"q": query, "per_page": min(max_results, 30)},
                                    timeout=15)
            if resp.status_code == 403:
                # Rate limited — wait
                reset = int(resp.headers.get("X-RateLimit-Reset", 0))
                wait = max(reset - int(time.time()), 10)
                time.sleep(min(wait, 60))
                resp = self.session.get(f"{GITHUB_API}/search/code",
                                        params={"q": query, "per_page": min(max_results, 30)},
                                        timeout=15)
            if resp.status_code != 200:
                return [{"error": f"HTTP {resp.status_code}"}]

            results = []
            for item in resp.json().get("items", [])[:max_results]:
                results.append({
                    "repo": item.get("repository", {}).get("full_name", ""),
                    "path": item.get("path", ""),
                    "url": item.get("html_url", ""),
                    "score": item.get("score", 0),
                })
            return results
        except Exception as e:
            return [{"error": str(e)}]

    def dork(self, domain: str, categories: list = None) -> dict:
        """Run all dork patterns for a domain."""
        cats = categories or list(self.DORK_TEMPLATES.keys())
        results = {"domain": domain, "categories": {}, "total_results": 0}

        for cat in cats:
            patterns = self.DORK_TEMPLATES.get(cat, [])
            cat_results = []

            for pattern in patterns:
                query = pattern.format(domain=domain)
                hits = self.search_code(query, max_results=5)
                clean = [h for h in hits if not h.get("error")]

                if clean:
                    cat_results.extend([{**h, "query": query} for h in clean])
                    for h in clean:
                        self.findings.append({
                            "type": f"github_{cat}",
                            "severity": "HIGH" if cat in ("secrets", "credentials") else "MEDIUM",
                            "query": query,
                            "repo": h.get("repo", ""),
                            "url": h.get("url", ""),
                        })

                time.sleep(2)  # GitHub rate limit

            results["categories"][cat] = cat_results
            results["total_results"] += len(cat_results)

        return results

    def quick_scan(self, domain: str) -> list:
        """Fast scan — top 5 most impactful dorks only."""
        top_dorks = [
            f'"{domain}" filename:.env',
            f'"{domain}" password',
            f'"{domain}" api_key OR apikey OR api-key',
            f'"{domain}" secret OR token',
            f'"{domain}" s3.amazonaws.com OR firebase',
        ]
        all_results = []
        for query in top_dorks:
            hits = self.search_code(query, max_results=5)
            all_results.extend([h for h in hits if not h.get("error")])
            time.sleep(2)
        return all_results

    def save_results(self, target: str):
        out = Path(f"findings/{target}/github_dorks")
        out.mkdir(parents=True, exist_ok=True)
        (out / f"dorks_{int(time.time())}.json").write_text(
            json.dumps(self.findings, indent=2, default=str), encoding="utf-8")
