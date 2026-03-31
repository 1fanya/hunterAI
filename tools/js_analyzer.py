#!/usr/bin/env python3
"""
JS Analyzer — JavaScript Bundle Analysis for Bug Bounty

Extracts from JS files:
- API endpoints and routes
- Hardcoded secrets (API keys, tokens, passwords)
- Hidden admin/debug routes
- Framework/library detection with versions
- WebSocket endpoints
- Cloud service references (S3, Firebase, etc.)

Usage:
    python3 js_analyzer.py --target target.com --recon-dir recon/target.com/
    python3 js_analyzer.py --url https://target.com/static/app.js
    python3 js_analyzer.py --file /tmp/downloaded.js
"""

import argparse
import json
import os
import re
import sys
from datetime import datetime
from urllib.request import Request, urlopen
from urllib.error import HTTPError, URLError

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

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


# Regex patterns for extracting valuable data from JS
PATTERNS = {
    "api_endpoints": [
        r'["\']/(api|v\d+|graphql|rest|internal|admin|auth|oauth|ws)(/[a-zA-Z0-9/_\-{}:.]+)["\']',
        r'["\']https?://[a-zA-Z0-9.-]+(/[a-zA-Z0-9/_\-{}:.?=&]+)["\']',
        r'fetch\s*\(\s*["\']([^"\']+)["\']',
        r'axios\.\w+\s*\(\s*["\']([^"\']+)["\']',
        r'\.get\s*\(\s*["\']([^"\']+)["\']',
        r'\.post\s*\(\s*["\']([^"\']+)["\']',
        r'\.put\s*\(\s*["\']([^"\']+)["\']',
        r'\.delete\s*\(\s*["\']([^"\']+)["\']',
        r'url\s*[=:]\s*["\']([^"\']*(?:api|v\d|auth|admin)[^"\']*)["\']',
    ],
    "secrets": [
        (r'["\']?(?:api[_-]?key|apikey)["\']?\s*[=:]\s*["\']([a-zA-Z0-9_\-]{20,})["\']', "api_key"),
        (r'["\']?(?:secret|client_secret)["\']?\s*[=:]\s*["\']([a-zA-Z0-9_\-/+=]{20,})["\']', "secret"),
        (r'["\']?(?:token|access_token|auth_token)["\']?\s*[=:]\s*["\']([a-zA-Z0-9_\-/+=.]{20,})["\']', "token"),
        (r'["\']?(?:password|passwd|pwd)["\']?\s*[=:]\s*["\']([^"\']{8,})["\']', "password"),
        (r'(?:AKIA[A-Z0-9]{16})', "aws_access_key"),
        (r'(?:ghp_[a-zA-Z0-9]{36})', "github_token"),
        (r'(?:sk-[a-zA-Z0-9]{48})', "openai_key"),
        (r'(?:xox[bpas]-[a-zA-Z0-9\-]+)', "slack_token"),
        (r'(?:AIza[a-zA-Z0-9_\-]{35})', "google_api_key"),
        (r'(?:sq0[a-z]{3}-[a-zA-Z0-9_\-]{22,})', "square_key"),
        (r'(?:sk_live_[a-zA-Z0-9]{24,})', "stripe_key"),
        (r'(?:pk_live_[a-zA-Z0-9]{24,})', "stripe_pub_key"),
    ],
    "admin_routes": [
        r'["\']/(admin|dashboard|internal|debug|_debug|management|backstage|superadmin)[/\w]*["\']',
        r'["\']/(actuator|metrics|health|status|swagger|api-docs|graphiql)[/\w]*["\']',
        r'["\']/(phpmyadmin|adminer|wp-admin|wp-login|elmah|trace)[/\w]*["\']',
    ],
    "cloud_refs": [
        (r'([a-zA-Z0-9._-]+\.s3\.amazonaws\.com)', "s3_bucket"),
        (r'([a-zA-Z0-9._-]+\.s3-[a-z0-9-]+\.amazonaws\.com)', "s3_bucket_regional"),
        (r'([a-zA-Z0-9._-]+\.firebaseio\.com)', "firebase"),
        (r'([a-zA-Z0-9._-]+\.firebaseapp\.com)', "firebase_app"),
        (r'([a-zA-Z0-9._-]+\.cloudfront\.net)', "cloudfront"),
        (r'([a-zA-Z0-9._-]+\.herokuapp\.com)', "heroku"),
        (r'([a-zA-Z0-9._-]+\.azurewebsites\.net)', "azure"),
        (r'([a-zA-Z0-9._-]+\.blob\.core\.windows\.net)', "azure_blob"),
    ],
    "websocket": [
        r'wss?://[a-zA-Z0-9._\-/]+',
    ],
}


def download_js(url, timeout=15):
    """Download JS file content."""
    try:
        req = Request(url, headers={"User-Agent": "Mozilla/5.0"})
        with urlopen(req, timeout=timeout) as resp:
            return resp.read().decode("utf-8", errors="replace")
    except (HTTPError, URLError) as e:
        log("warn", f"Could not download {url}: {e}")
        return ""


def analyze_js(content, source_name="unknown"):
    """Analyze JS content for security-relevant data."""
    results = {
        "source": source_name,
        "api_endpoints": [],
        "secrets": [],
        "admin_routes": [],
        "cloud_refs": [],
        "websockets": [],
        "frameworks": [],
    }

    if not content:
        return results

    # Extract API endpoints
    endpoints = set()
    for pattern in PATTERNS["api_endpoints"]:
        for match in re.finditer(pattern, content, re.IGNORECASE):
            endpoint = match.group(1) if match.lastindex else match.group(0)
            endpoint = endpoint.strip("'\"")
            if len(endpoint) > 3 and not endpoint.startswith("//"):
                endpoints.add(endpoint)
    results["api_endpoints"] = sorted(endpoints)

    # Extract secrets
    for pattern, secret_type in PATTERNS["secrets"]:
        for match in re.finditer(pattern, content, re.IGNORECASE):
            value = match.group(1) if match.lastindex and match.lastindex >= 1 else match.group(0)
            # Filter out common false positives
            if not _is_false_positive_secret(value):
                results["secrets"].append({
                    "type": secret_type,
                    "value": value[:8] + "..." + value[-4:] if len(value) > 16 else value,
                    "full_length": len(value),
                    "context": _get_context(content, match.start(), 50),
                })

    # Extract admin routes
    admin_routes = set()
    for pattern in PATTERNS["admin_routes"]:
        for match in re.finditer(pattern, content, re.IGNORECASE):
            route = match.group(0).strip("'\"")
            admin_routes.add(route)
    results["admin_routes"] = sorted(admin_routes)

    # Extract cloud references
    for pattern, cloud_type in PATTERNS["cloud_refs"]:
        for match in re.finditer(pattern, content, re.IGNORECASE):
            results["cloud_refs"].append({
                "type": cloud_type,
                "value": match.group(1) if match.lastindex else match.group(0),
            })

    # Extract WebSocket endpoints
    for pattern in PATTERNS["websocket"]:
        for match in re.finditer(pattern, content, re.IGNORECASE):
            results["websockets"].append(match.group(0))

    # Detect frameworks
    results["frameworks"] = _detect_frameworks(content)

    return results


def _is_false_positive_secret(value):
    """Filter out common false positive secrets."""
    if len(value) < 10:
        return True
    # Common placeholder values
    fp_patterns = [
        "XXXXXXXX", "example", "placeholder", "YOUR_", "CHANGE_ME",
        "undefined", "null", "true", "false", "function",
        "0123456789", "abcdefghij", "test", "dummy", "sample",
    ]
    for fp in fp_patterns:
        if fp.lower() in value.lower():
            return True
    # All same character
    if len(set(value.replace("-", "").replace("_", ""))) < 3:
        return True
    return False


def _get_context(content, pos, chars=50):
    """Get surrounding context for a match."""
    start = max(0, pos - chars)
    end = min(len(content), pos + chars)
    return content[start:end].strip()


def _detect_frameworks(content):
    """Detect JS frameworks and libraries."""
    frameworks = []
    detections = {
        "React": [r'react["\s]', r'React\.createElement', r'__REACT'],
        "Angular": [r'angular\.\w+', r'@angular/', r'ng-app'],
        "Vue.js": [r'vue["\s]', r'Vue\.\w+', r'__VUE'],
        "Next.js": [r'__NEXT_DATA__', r'next/router'],
        "jQuery": [r'jquery', r'\$\.\w+\('],
        "Express": [r'express\(\)', r'app\.listen'],
        "Webpack": [r'webpackJsonp', r'__webpack_'],
        "GraphQL": [r'graphql', r'__typename', r'mutation\s*{'],
    }
    for fw, patterns in detections.items():
        for pattern in patterns:
            if re.search(pattern, content, re.IGNORECASE):
                frameworks.append(fw)
                break
    return frameworks


def analyze_target(target, recon_dir=None):
    """Analyze all JS files for a target."""
    all_results = []

    if recon_dir and os.path.isdir(recon_dir):
        # Find JS URLs from recon data
        urls_file = os.path.join(recon_dir, "urls.txt")
        if os.path.exists(urls_file):
            with open(urls_file) as f:
                urls = [line.strip() for line in f if line.strip()]
            js_urls = [u for u in urls if re.search(r'\.js(\?|$)', u, re.IGNORECASE)]
            log("info", f"Found {len(js_urls)} JS files in recon data")

            for url in js_urls[:50]:  # Limit to 50 JS files
                log("info", f"Analyzing: {url}")
                content = download_js(url)
                if content:
                    result = analyze_js(content, source_name=url)
                    if any([result["api_endpoints"], result["secrets"],
                            result["admin_routes"], result["cloud_refs"]]):
                        all_results.append(result)
    else:
        # Analyze main page JS
        main_url = f"https://{target}"
        log("info", f"Fetching main page: {main_url}")
        content = download_js(main_url)
        if content:
            # Extract JS file URLs from HTML
            js_urls = re.findall(r'src=["\']((?:https?://)?[^"\']+\.js(?:\?[^"\']*)?)["\']',
                                content, re.IGNORECASE)
            for js_url in js_urls[:20]:
                if not js_url.startswith("http"):
                    js_url = f"https://{target}/{js_url.lstrip('/')}"
                log("info", f"Analyzing: {js_url}")
                js_content = download_js(js_url)
                if js_content:
                    result = analyze_js(js_content, source_name=js_url)
                    if any([result["api_endpoints"], result["secrets"],
                            result["admin_routes"], result["cloud_refs"]]):
                        all_results.append(result)

    return all_results


def print_results(results):
    """Pretty-print analysis results."""
    all_endpoints = set()
    all_secrets = []
    all_admin = set()
    all_cloud = []
    all_frameworks = set()

    for r in results:
        all_endpoints.update(r["api_endpoints"])
        all_secrets.extend(r["secrets"])
        all_admin.update(r["admin_routes"])
        all_cloud.extend(r["cloud_refs"])
        all_frameworks.update(r["frameworks"])

    print(f"\n{BOLD}{'='*60}{NC}")
    print(f"{BOLD}  JS Analysis Results{NC}")
    print(f"{BOLD}{'='*60}{NC}\n")

    print(f"  Files analyzed: {len(results)}")
    print(f"  Frameworks detected: {', '.join(all_frameworks) if all_frameworks else 'none'}")

    if all_endpoints:
        print(f"\n  {CYAN}API Endpoints ({len(all_endpoints)}):{NC}")
        for ep in sorted(all_endpoints)[:30]:
            print(f"    → {ep}")
        if len(all_endpoints) > 30:
            print(f"    ... and {len(all_endpoints) - 30} more")

    if all_secrets:
        print(f"\n  {RED}Secrets Found ({len(all_secrets)}):{NC}")
        for s in all_secrets:
            print(f"    🔑 [{s['type']}] {s['value']} (length: {s['full_length']})")

    if all_admin:
        print(f"\n  {YELLOW}Admin/Debug Routes ({len(all_admin)}):{NC}")
        for route in sorted(all_admin):
            print(f"    ⚠ {route}")

    if all_cloud:
        print(f"\n  {CYAN}Cloud References ({len(all_cloud)}):{NC}")
        seen = set()
        for c in all_cloud:
            key = f"{c['type']}:{c['value']}"
            if key not in seen:
                print(f"    ☁ [{c['type']}] {c['value']}")
                seen.add(key)

    print(f"\n{'='*60}\n")


def save_results(results, target, output_dir=None):
    """Save analysis results."""
    if not output_dir:
        output_dir = os.path.join(BASE_DIR, "recon", target)
    os.makedirs(output_dir, exist_ok=True)

    filepath = os.path.join(output_dir, "js_analysis.json")
    with open(filepath, "w") as f:
        json.dump({
            "target": target,
            "files_analyzed": len(results),
            "results": results,
            "analyzed_at": datetime.now().isoformat(),
        }, f, indent=2)

    log("ok", f"Results saved to {filepath}")

    # Also save extracted endpoints as a file for other tools
    all_endpoints = set()
    for r in results:
        all_endpoints.update(r["api_endpoints"])

    if all_endpoints:
        ep_file = os.path.join(output_dir, "js_endpoints.txt")
        with open(ep_file, "w") as f:
            f.write("\n".join(sorted(all_endpoints)))
        log("ok", f"Extracted {len(all_endpoints)} endpoints to {ep_file}")


def main():
    parser = argparse.ArgumentParser(description="JS Bundle Analyzer")
    parser.add_argument("--target", help="Target domain")
    parser.add_argument("--recon-dir", help="Recon directory with urls.txt")
    parser.add_argument("--url", help="Analyze a single JS URL")
    parser.add_argument("--file", help="Analyze a local JS file")
    parser.add_argument("--json", action="store_true", help="JSON output")
    args = parser.parse_args()

    if args.file:
        with open(args.file) as f:
            content = f.read()
        results = [analyze_js(content, source_name=args.file)]
    elif args.url:
        content = download_js(args.url)
        results = [analyze_js(content, source_name=args.url)]
    elif args.target:
        results = analyze_target(args.target, args.recon_dir)
    else:
        log("err", "Provide --target, --url, or --file")
        sys.exit(1)

    if args.json:
        print(json.dumps(results, indent=2))
    else:
        print_results(results)

    if args.target:
        save_results(results, args.target)


if __name__ == "__main__":
    main()
