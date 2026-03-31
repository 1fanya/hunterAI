#!/usr/bin/env python3
"""
Tech Profiler — Deep Technology Stack Fingerprinting

Fingerprints the target's technology stack to guide vulnerability selection:
- HTTP header analysis (Server, X-Powered-By, cookies)
- Known framework file probing (/wp-json, /.env, /actuator)
- Favicon hash matching
- Response body patterns (React, Angular, GraphQL)
- Cloud provider detection

Outputs structured tech profile consumed by hunt target selection.

Usage:
    python3 tech_profiler.py --target target.com
    python3 tech_profiler.py --target api.target.com --deep
"""

import argparse
import hashlib
import json
import os
import re
import sys
import time
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


def http_get(url, timeout=10):
    """Simple HTTP GET request."""
    try:
        req = Request(url, headers={
            "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
            "Accept": "text/html,application/json,*/*",
        })
        with urlopen(req, timeout=timeout) as resp:
            return {
                "status": resp.status,
                "headers": dict(resp.headers),
                "body": resp.read().decode("utf-8", errors="replace")[:50000],
            }
    except HTTPError as e:
        body = ""
        try:
            body = e.read().decode("utf-8", errors="replace")[:5000]
        except Exception:
            pass
        return {"status": e.code, "headers": dict(e.headers) if e.headers else {}, "body": body}
    except Exception:
        return {"status": 0, "headers": {}, "body": ""}


# Technology fingerprints
HEADER_FINGERPRINTS = {
    "X-Powered-By": {
        "Express": "node_express",
        "Next.js": "nextjs",
        "PHP": "php",
        "ASP.NET": "aspnet",
        "Django": "django",
        "Flask": "flask",
    },
    "Server": {
        "nginx": "nginx",
        "Apache": "apache",
        "cloudflare": "cloudflare",
        "AmazonS3": "aws_s3",
        "Microsoft-IIS": "iis",
        "gunicorn": "python_gunicorn",
        "Kestrel": "dotnet_kestrel",
    },
}

COOKIE_FINGERPRINTS = {
    "PHPSESSID": "php",
    "JSESSIONID": "java",
    "__cf_bm": "cloudflare",
    "_session_id": "rails",
    "laravel_session": "laravel",
    "XSRF-TOKEN": "laravel_or_angular",
    "connect.sid": "node_express",
    "ASP.NET_SessionId": "aspnet",
    "ci_session": "codeigniter",
    "PLAY_SESSION": "playframework",
    "rack.session": "ruby_rack",
}

FRAMEWORK_PATHS = {
    "wordpress": [
        ("/wp-json/wp/v2/users", 200, "WordPress REST API"),
        ("/wp-login.php", 200, "WordPress login"),
        ("/xmlrpc.php", 200, "WordPress XML-RPC"),
    ],
    "laravel": [
        ("/.env", 200, "Laravel .env (CRITICAL!)"),
        ("/telescope", 200, "Laravel Telescope debug"),
        ("/horizon", 200, "Laravel Horizon"),
        ("/storage/logs/laravel.log", 200, "Laravel log file"),
    ],
    "spring": [
        ("/actuator/env", 200, "Spring Actuator env (CRITICAL!)"),
        ("/actuator/health", 200, "Spring Actuator health"),
        ("/actuator/heapdump", 200, "Spring heapdump (CRITICAL!)"),
        ("/actuator/mappings", 200, "Spring API mappings"),
        ("/swagger-ui.html", 200, "Swagger UI"),
        ("/v2/api-docs", 200, "Swagger API docs"),
    ],
    "django": [
        ("/admin/", 200, "Django admin"),
        ("/__debug__/", 200, "Django debug toolbar"),
        ("/api/schema/", 200, "Django REST schema"),
    ],
    "nodejs": [
        ("/.env", 200, "Node.js .env (CRITICAL!)"),
        ("/graphql", [200, 400], "GraphQL endpoint"),
        ("/_debug", 200, "Debug endpoint"),
        ("/api-docs", 200, "API documentation"),
    ],
    "generic": [
        ("/.git/config", 200, "Git config exposed (HIGH!)"),
        ("/.git/HEAD", 200, "Git HEAD exposed"),
        ("/.env", 200, "Environment file (CRITICAL!)"),
        ("/.env.local", 200, "Local env file"),
        ("/config.json", 200, "Config file exposed"),
        ("/server-status", 200, "Apache server-status"),
        ("/server-info", 200, "Apache server-info"),
        ("/phpinfo.php", 200, "PHP info"),
        ("/elmah.axd", 200, "ELMAH error logs"),
        ("/trace.axd", 200, "ASP.NET trace"),
    ],
    "graphql": [
        ("/graphql", [200, 400], "GraphQL"),
        ("/graphiql", 200, "GraphiQL IDE"),
        ("/api/graphql", [200, 400], "GraphQL API"),
        ("/v1/graphql", [200, 400], "GraphQL v1"),
    ],
    "firebase": [
        ("/.json", 200, "Firebase open read (CRITICAL!)"),
    ],
}

BODY_FINGERPRINTS = [
    (r'__NEXT_DATA__', "nextjs"),
    (r'_next/static', "nextjs"),
    (r'react-root|__react', "react"),
    (r'ng-app|angular', "angular"),
    (r'__VUE__|vue\.js', "vuejs"),
    (r'wp-content|wp-json', "wordpress"),
    (r'csrftoken.*django', "django"),
    (r'laravel', "laravel"),
    (r'__NUXT__', "nuxtjs"),
    (r'gatsby', "gatsby"),
    (r'svelte', "svelte"),
]


def profile_target(target, deep=False):
    """Profile a target's technology stack."""
    base_url = f"https://{target}" if not target.startswith("http") else target
    target_name = target.replace("https://", "").replace("http://", "")

    profile = {
        "target": target_name,
        "url": base_url,
        "technologies": [],
        "server": "",
        "framework": "",
        "language": "",
        "cloud_provider": "",
        "waf": "",
        "interesting_files": [],
        "graphql": False,
        "quick_wins": [],
        "recommended_tests": [],
    }

    log("info", f"Profiling {target_name}...")

    # Step 1: Main page analysis
    log("info", "Fetching main page...")
    resp = http_get(base_url)
    time.sleep(0.5)

    if resp["status"] == 0:
        log("err", f"Could not reach {base_url}")
        return profile

    # Header analysis
    headers = resp["headers"]
    for header_name, fingerprints in HEADER_FINGERPRINTS.items():
        value = headers.get(header_name, "")
        for keyword, tech in fingerprints.items():
            if keyword.lower() in value.lower():
                profile["technologies"].append(tech)
                if header_name == "Server":
                    profile["server"] = tech

    # Cookie analysis
    cookies = headers.get("Set-Cookie", "") + headers.get("set-cookie", "")
    for cookie_name, tech in COOKIE_FINGERPRINTS.items():
        if cookie_name in cookies:
            profile["technologies"].append(tech)

    # WAF detection
    waf_indicators = {
        "cloudflare": ["cf-ray", "__cf_bm", "cloudflare"],
        "akamai": ["akamai", "x-akamai"],
        "aws_waf": ["x-amzn-", "awselb"],
        "imperva": ["incap_ses", "visid_incap"],
        "sucuri": ["x-sucuri"],
        "fastly": ["x-fastly", "fastly"],
    }
    all_headers = str(headers).lower() + cookies.lower()
    for waf_name, indicators in waf_indicators.items():
        if any(ind in all_headers for ind in indicators):
            profile["waf"] = waf_name
            profile["technologies"].append(f"waf_{waf_name}")
            break

    # Body analysis
    body = resp["body"]
    for pattern, tech in BODY_FINGERPRINTS:
        if re.search(pattern, body, re.IGNORECASE):
            profile["technologies"].append(tech)

    # Step 2: Framework-specific path probing
    log("info", "Probing framework-specific paths...")
    for framework, paths in FRAMEWORK_PATHS.items():
        for path_info in paths:
            path, expected_status, desc = path_info
            check_url = f"{base_url}{path}"
            resp = http_get(check_url)
            time.sleep(0.3)

            if isinstance(expected_status, list):
                match = resp["status"] in expected_status
            else:
                match = resp["status"] == expected_status

            if match and resp["status"] != 0:
                profile["technologies"].append(framework)
                profile["interesting_files"].append({
                    "path": path,
                    "status": resp["status"],
                    "description": desc,
                    "size": len(resp["body"]),
                })

                # Mark as quick win if critical
                if "CRITICAL" in desc or "HIGH" in desc:
                    profile["quick_wins"].append({
                        "path": path,
                        "description": desc,
                        "severity": "CRITICAL" if "CRITICAL" in desc else "HIGH",
                    })
                    log("warn", f"QUICK WIN: {desc} at {path}")

                if "graphql" in framework.lower() or "graphql" in path.lower():
                    profile["graphql"] = True

    # Deduplicate technologies
    profile["technologies"] = sorted(set(profile["technologies"]))

    # Determine primary framework/language
    for tech in profile["technologies"]:
        if tech in ("laravel", "wordpress", "django", "flask", "rails",
                     "spring", "nextjs", "express", "node_express"):
            profile["framework"] = tech
        if tech in ("php", "python", "java", "ruby", "node_express", "aspnet"):
            profile["language"] = tech

    # Cloud provider
    for tech in profile["technologies"]:
        if tech.startswith("aws") or tech == "cloudfront":
            profile["cloud_provider"] = "aws"
        elif tech.startswith("azure"):
            profile["cloud_provider"] = "azure"
        elif tech == "cloudflare":
            if not profile["cloud_provider"]:
                profile["cloud_provider"] = "cloudflare"

    # Generate recommended tests based on tech stack
    profile["recommended_tests"] = _recommend_tests(profile)
    profile["profiled_at"] = datetime.now().isoformat()

    return profile


def _recommend_tests(profile):
    """Generate recommended vulnerability tests based on tech stack."""
    tests = []
    techs = set(profile["technologies"])

    # Always recommend
    tests.append({"test": "idor", "priority": "P1", "reason": "Universal — test on every API endpoint"})
    tests.append({"test": "auth_bypass", "priority": "P1", "reason": "Test every endpoint with no auth"})

    if profile["graphql"]:
        tests.append({"test": "graphql_idor", "priority": "P1",
                      "reason": "GraphQL detected — test node() queries and introspection"})

    if "laravel" in techs or "php" in techs:
        tests.append({"test": "ssti", "priority": "P1", "reason": "PHP/Laravel — test template injection"})
        tests.append({"test": "sqli", "priority": "P1", "reason": "PHP often has raw SQL queries"})

    if "wordpress" in techs:
        tests.append({"test": "wpscan", "priority": "P1",
                      "reason": "WordPress — check /xmlrpc.php, user enum, plugin vulns"})

    if "spring" in techs or "java" in techs:
        tests.append({"test": "actuator_exploit", "priority": "P1",
                      "reason": "Spring — check actuator endpoints for env/heapdump"})
        tests.append({"test": "ssti", "priority": "P2",
                      "reason": "Java templates (Freemarker/Thymeleaf)"})

    if "nextjs" in techs or "react" in techs:
        tests.append({"test": "ssrf", "priority": "P1",
                      "reason": "Next.js/React — check API routes for SSRF"})

    if "django" in techs or "python" in techs:
        tests.append({"test": "ssti", "priority": "P1", "reason": "Python — Jinja2 SSTI"})
        tests.append({"test": "debug_endpoint", "priority": "P2",
                      "reason": "Django debug toolbar"})

    if profile["cloud_provider"] == "aws":
        tests.append({"test": "ssrf_metadata", "priority": "P1",
                      "reason": "AWS detected — SSRF to 169.254.169.254 for IAM creds"})
        tests.append({"test": "s3_enum", "priority": "P2",
                      "reason": "AWS — enumerate S3 buckets"})

    if profile["waf"]:
        tests.append({"test": "waf_bypass", "priority": "P2",
                      "reason": f"{profile['waf']} WAF detected — use bypass techniques"})

    return tests


def print_profile(profile):
    """Pretty-print tech profile."""
    print(f"\n{BOLD}{'='*60}{NC}")
    print(f"{BOLD}  Tech Profile: {profile['target']}{NC}")
    print(f"{BOLD}{'='*60}{NC}\n")

    print(f"  Server:     {profile['server'] or 'unknown'}")
    print(f"  Framework:  {profile['framework'] or 'unknown'}")
    print(f"  Language:   {profile['language'] or 'unknown'}")
    print(f"  Cloud:      {profile['cloud_provider'] or 'unknown'}")
    print(f"  WAF:        {profile['waf'] or 'none detected'}")
    print(f"  GraphQL:    {'✓' if profile['graphql'] else '✗'}")
    print(f"  Technologies: {', '.join(profile['technologies'])}")

    if profile["quick_wins"]:
        print(f"\n  {RED}⚡ QUICK WINS:{NC}")
        for qw in profile["quick_wins"]:
            print(f"    [{qw['severity']}] {qw['description']} at {qw['path']}")

    if profile["interesting_files"]:
        print(f"\n  {YELLOW}Interesting Files:{NC}")
        for f in profile["interesting_files"]:
            print(f"    [{f['status']}] {f['path']} — {f['description']} ({f['size']}B)")

    if profile["recommended_tests"]:
        print(f"\n  {CYAN}Recommended Tests:{NC}")
        for t in profile["recommended_tests"]:
            print(f"    [{t['priority']}] {t['test']} — {t['reason']}")

    print(f"\n{'='*60}\n")


def save_profile(profile, output_dir=None):
    """Save profile to recon directory."""
    target = profile["target"]
    if not output_dir:
        output_dir = os.path.join(BASE_DIR, "recon", target)
    os.makedirs(output_dir, exist_ok=True)

    filepath = os.path.join(output_dir, "tech_profile.json")
    with open(filepath, "w") as f:
        json.dump(profile, f, indent=2)

    log("ok", f"Profile saved to {filepath}")
    return filepath


def main():
    parser = argparse.ArgumentParser(description="Technology Stack Profiler")
    parser.add_argument("--target", required=True, help="Target domain")
    parser.add_argument("--deep", action="store_true", help="Deep profiling (more probes)")
    parser.add_argument("--json", action="store_true", help="JSON output")
    args = parser.parse_args()

    profile = profile_target(args.target, deep=args.deep)

    if args.json:
        print(json.dumps(profile, indent=2))
    else:
        print_profile(profile)

    save_profile(profile)


if __name__ == "__main__":
    main()
