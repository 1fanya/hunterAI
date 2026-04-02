#!/usr/bin/env python3
"""
Param Miner — Hidden parameter discovery for API endpoints.

Discovers undocumented parameters that can unlock:
  - Debug modes (?debug=1, ?verbose=true)
  - Admin access (?admin=true, ?role=admin)
  - IDOR vectors (?user_id=, ?account_id=)
  - SSRF entry points (?url=, ?callback=, ?redirect=)
  - Hidden features (?beta=1, ?internal=true)

Uses response diffing to detect parameters that change behavior.
Integrates with SecLists parameter wordlists for comprehensive coverage.

Usage:
    python3 param_miner.py --url https://api.target.com/endpoint --method GET
    python3 param_miner.py --url https://api.target.com/users --method POST \
        --auth "Bearer eyJ..."
    python3 param_miner.py --url https://api.target.com/endpoint --wordlist custom.txt
"""

import argparse
import json
import os
import re
import sys
import time
from datetime import datetime, timezone
from urllib.parse import urlparse, urlencode, parse_qs, urlunparse

try:
    import urllib.request
    import urllib.error
except ImportError:
    pass

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FINDINGS_DIR = os.path.join(BASE_DIR, "findings")
WORDLIST_DIR = os.path.join(BASE_DIR, "wordlists")

GREEN = "\033[0;32m"
RED = "\033[0;31m"
YELLOW = "\033[1;33m"
CYAN = "\033[0;36m"
BOLD = "\033[1m"
NC = "\033[0m"


def log(level, msg):
    colors = {"ok": GREEN, "err": RED, "warn": YELLOW, "info": CYAN}
    symbols = {"ok": "+", "err": "-", "warn": "!", "info": "*"}
    print(f"{colors.get(level, '')}{BOLD}[{symbols.get(level, '*')}]{NC} {msg}")


# Built-in high-value parameter names (most impactful for bug bounty)
BUILTIN_PARAMS = [
    # Debug/admin
    "debug", "verbose", "test", "testing", "dev", "internal",
    "admin", "is_admin", "isAdmin", "role", "privilege", "level",
    "mode", "view", "action", "cmd", "command", "exec",
    # Auth/user reference
    "user_id", "userId", "uid", "account_id", "accountId",
    "owner", "owner_id", "ownerId", "author_id",
    "email", "username", "login",
    "token", "api_key", "apiKey", "access_token", "auth",
    # SSRF targets
    "url", "uri", "link", "href", "src", "source",
    "redirect", "redirect_url", "redirect_uri", "return_url",
    "next", "next_url", "callback", "callback_url",
    "dest", "destination", "target", "goto", "out", "continue",
    "proxy", "fetch", "load", "request", "file", "path",
    "webhook", "webhook_url", "notify_url",
    # Template/injection
    "template", "tpl", "page", "include", "require",
    "render", "layout", "theme", "skin",
    # Data format
    "format", "type", "output", "content_type", "accept",
    "lang", "language", "locale", "timezone",
    # Filter/query
    "q", "query", "search", "filter", "sort", "order",
    "limit", "offset", "page", "per_page", "perPage", "size",
    "fields", "select", "expand", "include", "embed",
    # File operations
    "filename", "file", "filepath", "upload", "download",
    "export", "import", "attachment",
    # Financial/business
    "amount", "price", "quantity", "qty", "discount",
    "coupon", "promo", "code", "voucher",
    # Version/feature
    "version", "v", "api_version", "feature", "flag",
    "beta", "experimental", "preview",
]


def http_request(url, method="GET", headers=None, data=None, timeout=10):
    """Make HTTP request and return response fingerprint."""
    try:
        if method == "GET" or data is None:
            req = urllib.request.Request(url, method=method)
        else:
            if isinstance(data, dict):
                data = urlencode(data).encode()
            elif isinstance(data, str):
                data = data.encode()
            req = urllib.request.Request(url, data=data, method=method)

        req.add_header("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0")
        if headers:
            for k, v in headers.items():
                req.add_header(k, v)

        if method == "POST" and not headers.get("Content-Type"):
            req.add_header("Content-Type", "application/x-www-form-urlencoded")

        start = time.time()
        resp = urllib.request.urlopen(req, timeout=timeout)
        elapsed = time.time() - start

        body = resp.read().decode("utf-8", errors="replace")
        return {
            "status": resp.getcode(),
            "size": len(body),
            "word_count": len(body.split()),
            "line_count": body.count("\n"),
            "time_ms": int(elapsed * 1000),
            "headers": dict(resp.getheaders()),
            "body": body,
        }
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", errors="replace") if e.fp else ""
        return {
            "status": e.code,
            "size": len(body),
            "word_count": len(body.split()),
            "line_count": body.count("\n"),
            "time_ms": 0,
            "headers": dict(e.headers),
            "body": body,
        }
    except Exception as e:
        return {"status": 0, "size": 0, "word_count": 0, "line_count": 0,
                "time_ms": 0, "headers": {}, "body": "", "error": str(e)}


class ParamMiner:
    """Discover hidden parameters on web endpoints."""

    def __init__(self, rate_limit=5.0):
        self.rate_limit = rate_limit
        self.findings = []

    def _load_wordlist(self, wordlist_path: str = None) -> list:
        """Load parameter wordlist. Falls back to built-in list."""
        params = list(BUILTIN_PARAMS)

        # Try SecLists parameter names
        seclists_paths = [
            os.path.join(WORDLIST_DIR, "params.txt"),
            "/usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt",
            os.path.expanduser("~/SecLists/Discovery/Web-Content/burp-parameter-names.txt"),
        ]

        if wordlist_path:
            seclists_paths.insert(0, wordlist_path)

        for path in seclists_paths:
            if os.path.exists(path):
                try:
                    with open(path) as f:
                        for line in f:
                            line = line.strip()
                            if line and not line.startswith("#"):
                                params.append(line)
                    log("info", f"Loaded wordlist: {path} ({len(params)} params)")
                    break
                except IOError:
                    continue

        return list(dict.fromkeys(params))  # Deduplicate preserving order

    def _get_baseline(self, url: str, method: str, headers: dict) -> dict:
        """Get baseline response for comparison."""
        if method == "GET":
            resp = http_request(url, method="GET", headers=headers)
        else:
            resp = http_request(url, method=method, headers=headers, data={})
        return resp

    def _is_different(self, baseline: dict, test_resp: dict) -> dict:
        """Compare test response to baseline. Returns diff details or None."""
        diffs = {}

        # Status code change
        if test_resp["status"] != baseline["status"]:
            diffs["status_change"] = {
                "from": baseline["status"],
                "to": test_resp["status"],
            }

        # Size difference (>10% change)
        if baseline["size"] > 0:
            size_diff = abs(test_resp["size"] - baseline["size"])
            size_pct = (size_diff / baseline["size"]) * 100
            if size_pct > 10:
                diffs["size_change"] = {
                    "from": baseline["size"],
                    "to": test_resp["size"],
                    "diff_pct": round(size_pct, 1),
                }

        # Response time anomaly (>3x slower = potential time-based)
        if baseline["time_ms"] > 0 and test_resp["time_ms"] > baseline["time_ms"] * 3:
            diffs["time_anomaly"] = {
                "baseline_ms": baseline["time_ms"],
                "test_ms": test_resp["time_ms"],
            }

        # New headers in response
        new_headers = set(test_resp["headers"].keys()) - set(baseline["headers"].keys())
        if new_headers:
            diffs["new_headers"] = list(new_headers)

        # Word count difference
        word_diff = abs(test_resp["word_count"] - baseline["word_count"])
        if word_diff > 5:
            diffs["word_count_change"] = {
                "from": baseline["word_count"],
                "to": test_resp["word_count"],
            }

        return diffs if diffs else None

    def _classify_param(self, param: str, diffs: dict, test_resp: dict) -> dict:
        """Classify a discovered parameter by its security impact."""
        classification = {
            "param": param,
            "impact": "info",
            "vuln_class": "unknown",
            "diffs": diffs,
        }

        param_lower = param.lower()

        # High impact: debug/admin modes
        if param_lower in ("debug", "admin", "is_admin", "role", "internal", "verbose", "test"):
            if "status_change" in diffs and diffs["status_change"]["to"] == 200:
                classification["impact"] = "high"
                classification["vuln_class"] = "access_control"

        # High impact: SSRF parameters
        elif param_lower in ("url", "uri", "callback", "redirect", "webhook", "fetch", "proxy", "load"):
            classification["impact"] = "high"
            classification["vuln_class"] = "ssrf_candidate"

        # High impact: user ID / IDOR parameters
        elif any(x in param_lower for x in ("user_id", "userid", "uid", "account", "owner")):
            classification["impact"] = "high"
            classification["vuln_class"] = "idor_candidate"

        # Medium impact: template/injection
        elif param_lower in ("template", "tpl", "page", "include", "render"):
            classification["impact"] = "medium"
            classification["vuln_class"] = "injection_candidate"

        # Medium: size/content change
        elif "size_change" in diffs and diffs["size_change"]["diff_pct"] > 50:
            classification["impact"] = "medium"
            classification["vuln_class"] = "data_exposure"

        # Time anomaly (potential blind injection)
        elif "time_anomaly" in diffs:
            classification["impact"] = "medium"
            classification["vuln_class"] = "blind_injection"

        return classification

    def mine(self, url: str, method: str = "GET", headers: dict = None,
             wordlist: str = None, batch_size: int = 10) -> list:
        """Discover hidden parameters on an endpoint.

        Uses response diffing: sends requests with each parameter and
        compares to baseline. Parameters that change the response are flagged.

        Args:
            url: Target endpoint URL
            method: GET or POST
            headers: Auth headers
            wordlist: Optional custom wordlist path
            batch_size: Number of params to test per request (GET batching)

        Returns:
            List of discovered parameters with classification
        """
        headers = headers or {}
        params = self._load_wordlist(wordlist)
        log("info", f"Mining {len(params)} params on {method} {url}")

        # Get baseline
        baseline = self._get_baseline(url, method, headers)
        if baseline.get("error") or baseline["status"] == 0:
            log("err", f"Cannot reach endpoint: {baseline.get('error', 'unknown')}")
            return []

        log("info", f"Baseline: status={baseline['status']} size={baseline['size']} time={baseline['time_ms']}ms")

        discovered = []
        tested = 0

        # Test params individually (more accurate but slower)
        for param in params:
            test_values = ["1", "true", "admin"]

            for val in test_values:
                if method == "GET":
                    parsed = urlparse(url)
                    existing_params = parse_qs(parsed.query)
                    existing_params[param] = val
                    new_query = urlencode(existing_params, doseq=True)
                    test_url = urlunparse(parsed._replace(query=new_query))
                    resp = http_request(test_url, method="GET", headers=headers)
                else:
                    resp = http_request(url, method=method, headers=headers,
                                       data={param: val})

                tested += 1
                diffs = self._is_different(baseline, resp)

                if diffs:
                    classification = self._classify_param(param, diffs, resp)
                    discovered.append(classification)

                    impact_color = {"high": RED, "medium": YELLOW, "info": CYAN}.get(
                        classification["impact"], NC)
                    log("ok", f"Found: {param}={val} [{impact_color}{classification['impact']}{NC}] "
                        f"({classification['vuln_class']})")

                    self.findings.append({
                        "param": param,
                        "value": val,
                        "url": url,
                        "method": method,
                        **classification,
                        "ts": datetime.now(timezone.utc).isoformat(),
                    })
                    break  # Found with this value, move to next param

                time.sleep(1.0 / self.rate_limit)

            # Progress
            if tested % 50 == 0:
                log("info", f"Progress: {tested}/{len(params)} tested, {len(discovered)} found")

        log("ok", f"Done: {tested} params tested, {len(discovered)} discovered")
        return discovered

    def save_findings(self, target_name: str):
        """Save discovered parameters to disk."""
        if not self.findings:
            return

        out_dir = os.path.join(FINDINGS_DIR, target_name)
        os.makedirs(out_dir, exist_ok=True)

        out_file = os.path.join(out_dir, "hidden_params.json")
        with open(out_file, "w") as f:
            json.dump(self.findings, f, indent=2)
        log("ok", f"Saved {len(self.findings)} params to {out_file}")


def main():
    parser = argparse.ArgumentParser(description="Hidden Parameter Discovery")
    parser.add_argument("--url", required=True, help="Target endpoint URL")
    parser.add_argument("--method", default="GET", help="HTTP method (GET/POST)")
    parser.add_argument("--auth", help="Authorization header value")
    parser.add_argument("--cookie", help="Cookie header value")
    parser.add_argument("--wordlist", help="Custom parameter wordlist")
    parser.add_argument("--rate", type=float, default=5.0, help="Requests per second")
    parser.add_argument("--target", help="Target name for saving results")
    args = parser.parse_args()

    headers = {}
    if args.auth:
        headers["Authorization"] = args.auth
    if args.cookie:
        headers["Cookie"] = args.cookie

    miner = ParamMiner(rate_limit=args.rate)
    results = miner.mine(args.url, method=args.method, headers=headers,
                         wordlist=args.wordlist)

    print(json.dumps(results, indent=2, default=str))

    if args.target:
        miner.save_findings(args.target)


if __name__ == "__main__":
    main()
