#!/usr/bin/env python3
"""
Scope Importer — Auto-fetch program scope from HackerOne/Bugcrowd

Queries bug bounty platform APIs to retrieve in-scope domains, excluded assets,
and program policy. Outputs a ScopeChecker-compatible allowlist.

Usage:
    python3 scope_importer.py --platform hackerone --program uber
    python3 scope_importer.py --platform hackerone --program shopify
    python3 scope_importer.py --domains "*.target.com,api.target.com" --exclude "blog.target.com"
"""

import argparse
import json
import os
import re
import subprocess
import sys
from datetime import datetime
from urllib.request import Request, urlopen
from urllib.error import HTTPError, URLError

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TARGETS_DIR = os.path.join(BASE_DIR, "targets")

# Colors
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


def fetch_hackerone_scope(program_handle, api_token=None):
    """Fetch scope from HackerOne GraphQL API.

    Args:
        program_handle: HackerOne program handle (e.g., 'uber', 'shopify')
        api_token: Optional HackerOne API token for authenticated requests

    Returns:
        dict with domains, excluded_domains, program_info
    """
    query = """
    query {
      team(handle: "%s") {
        name
        url
        policy_scopes(archived: false) {
          edges {
            node {
              asset_type
              asset_identifier
              eligible_for_bounty
              eligible_for_submission
              instruction
              max_severity
            }
          }
        }
      }
    }
    """ % program_handle

    headers = {"Content-Type": "application/json"}
    if api_token:
        headers["Authorization"] = f"Bearer {api_token}"

    data = json.dumps({"query": query}).encode("utf-8")
    req = Request("https://hackerone.com/graphql", data=data, headers=headers)

    try:
        with urlopen(req, timeout=30) as resp:
            result = json.loads(resp.read().decode("utf-8"))
    except HTTPError as e:
        log("err", f"HackerOne API error: {e.code} {e.reason}")
        return None
    except URLError as e:
        log("err", f"Network error: {e.reason}")
        return None

    team = result.get("data", {}).get("team")
    if not team:
        log("err", f"Program '{program_handle}' not found on HackerOne")
        return None

    scopes = team.get("policy_scopes", {}).get("edges", [])

    domains = []
    excluded_domains = []
    other_assets = []
    excluded_classes = []

    for edge in scopes:
        node = edge.get("node", {})
        asset_type = node.get("asset_type", "")
        identifier = node.get("asset_identifier", "")
        eligible = node.get("eligible_for_bounty", False)
        instruction = node.get("instruction", "") or ""

        if asset_type in ("URL", "DOMAIN", "WILDCARD"):
            # Clean up the identifier
            domain = identifier.strip()
            domain = re.sub(r'^https?://', '', domain)
            domain = domain.rstrip('/')

            if eligible:
                domains.append(domain)
            else:
                excluded_domains.append(domain)
        elif asset_type == "OTHER":
            other_assets.append({
                "identifier": identifier,
                "eligible": eligible,
                "instruction": instruction,
            })

        # Extract excluded vuln classes from instructions
        if instruction:
            lower_inst = instruction.lower()
            for cls in ["dos", "social_engineering", "phishing", "spam",
                        "clickjacking", "self-xss", "csv_injection"]:
                if cls.replace("_", " ") in lower_inst or cls in lower_inst:
                    if cls not in excluded_classes:
                        excluded_classes.append(cls)

    return {
        "program": {
            "name": team.get("name", program_handle),
            "handle": program_handle,
            "url": team.get("url", f"https://hackerone.com/{program_handle}"),
            "platform": "hackerone",
        },
        "domains": domains,
        "excluded_domains": excluded_domains,
        "excluded_classes": excluded_classes,
        "other_assets": other_assets,
        "fetched_at": datetime.now().isoformat(),
    }


def fetch_hackerone_hacktivity(program_handle, limit=25):
    """Fetch recent disclosed reports for dedup checking.

    Returns list of disclosed report summaries.
    """
    query = """
    {
      hacktivity_items(first: %d, order_by: {field: popular, direction: DESC},
        where: {team: {handle: {_eq: "%s"}}}) {
        nodes {
          ... on HacktivityDocument {
            report {
              title
              severity_rating
              substate
              disclosed_at
            }
          }
        }
      }
    }
    """ % (limit, program_handle)

    headers = {"Content-Type": "application/json"}
    data = json.dumps({"query": query}).encode("utf-8")
    req = Request("https://hackerone.com/graphql", data=data, headers=headers)

    try:
        with urlopen(req, timeout=30) as resp:
            result = json.loads(resp.read().decode("utf-8"))
    except (HTTPError, URLError) as e:
        log("warn", f"Could not fetch Hacktivity: {e}")
        return []

    nodes = result.get("data", {}).get("hacktivity_items", {}).get("nodes", [])
    reports = []
    for node in nodes:
        report = node.get("report", {})
        if report:
            reports.append({
                "title": report.get("title", ""),
                "severity": report.get("severity_rating", ""),
                "state": report.get("substate", ""),
                "disclosed_at": report.get("disclosed_at", ""),
            })
    return reports


def manual_scope(domains_str, exclude_str=None):
    """Create scope from manual domain input.

    Args:
        domains_str: Comma-separated domain list (e.g., "*.target.com,api.target.com")
        exclude_str: Optional comma-separated excluded domains
    """
    domains = [d.strip() for d in domains_str.split(",") if d.strip()]
    excluded = []
    if exclude_str:
        excluded = [d.strip() for d in exclude_str.split(",") if d.strip()]

    return {
        "program": {
            "name": domains[0].replace("*.", "") if domains else "unknown",
            "handle": "manual",
            "url": "",
            "platform": "manual",
        },
        "domains": domains,
        "excluded_domains": excluded,
        "excluded_classes": [],
        "other_assets": [],
        "fetched_at": datetime.now().isoformat(),
    }


def save_scope(scope_data, output_dir=None):
    """Save scope to targets directory for use by other tools."""
    if output_dir is None:
        output_dir = TARGETS_DIR
    os.makedirs(output_dir, exist_ok=True)

    program_name = scope_data["program"]["handle"]
    filepath = os.path.join(output_dir, f"{program_name}_scope.json")

    with open(filepath, "w") as f:
        json.dump(scope_data, f, indent=2)

    log("ok", f"Scope saved to {filepath}")
    return filepath


def print_scope(scope_data):
    """Pretty-print scope information."""
    prog = scope_data["program"]
    print(f"\n{BOLD}{'='*60}{NC}")
    print(f"{BOLD}  Program: {prog['name']}{NC}")
    print(f"  Platform: {prog['platform']}")
    print(f"  URL: {prog['url']}")
    print(f"{BOLD}{'='*60}{NC}\n")

    print(f"{GREEN}In-Scope Domains ({len(scope_data['domains'])}):{NC}")
    for d in scope_data["domains"]:
        print(f"  ✓ {d}")

    if scope_data["excluded_domains"]:
        print(f"\n{RED}Excluded Domains ({len(scope_data['excluded_domains'])}):{NC}")
        for d in scope_data["excluded_domains"]:
            print(f"  ✗ {d}")

    if scope_data["excluded_classes"]:
        print(f"\n{YELLOW}Excluded Vuln Classes:{NC}")
        for c in scope_data["excluded_classes"]:
            print(f"  ✗ {c}")

    if scope_data.get("other_assets"):
        print(f"\n{CYAN}Other Assets:{NC}")
        for a in scope_data["other_assets"]:
            status = "✓" if a["eligible"] else "✗"
            print(f"  {status} {a['identifier']}")

    print()


def generate_scope_checker_config(scope_data):
    """Generate Python code snippet for ScopeChecker initialization."""
    domains = scope_data["domains"]
    excluded = scope_data["excluded_domains"]
    excluded_classes = scope_data["excluded_classes"]

    code = f"""from scope_checker import ScopeChecker

scope = ScopeChecker(
    domains={json.dumps(domains, indent=8)},
    excluded_domains={json.dumps(excluded, indent=8)},
    excluded_classes={json.dumps(excluded_classes, indent=8)},
)
"""
    return code


def main():
    parser = argparse.ArgumentParser(
        description="Import bug bounty program scope",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 scope_importer.py --platform hackerone --program shopify
  python3 scope_importer.py --domains "*.target.com,api.target.com"
  python3 scope_importer.py --platform hackerone --program uber --hacktivity
        """,
    )
    parser.add_argument("--platform", choices=["hackerone", "bugcrowd", "manual"],
                        default="manual", help="Bug bounty platform")
    parser.add_argument("--program", type=str, help="Program handle (e.g., 'shopify')")
    parser.add_argument("--domains", type=str, help="Comma-separated domains for manual scope")
    parser.add_argument("--exclude", type=str, help="Comma-separated excluded domains")
    parser.add_argument("--hacktivity", action="store_true",
                        help="Also fetch disclosed reports for dedup")
    parser.add_argument("--output-dir", type=str, help="Output directory")
    parser.add_argument("--json", action="store_true", help="Output raw JSON")
    args = parser.parse_args()

    # Get API token from environment
    api_token = os.environ.get("H1_API_TOKEN", "")

    if args.platform == "hackerone":
        if not args.program:
            log("err", "Must provide --program for HackerOne (e.g., --program shopify)")
            sys.exit(1)

        log("info", f"Fetching scope for {args.program} from HackerOne...")
        scope_data = fetch_hackerone_scope(args.program, api_token=api_token or None)

        if not scope_data:
            sys.exit(1)

        if args.hacktivity:
            log("info", "Fetching disclosed reports for dedup checking...")
            reports = fetch_hackerone_hacktivity(args.program)
            scope_data["hacktivity"] = reports
            if reports:
                log("ok", f"Found {len(reports)} disclosed reports")
                print(f"\n{CYAN}Recent Disclosed Reports:{NC}")
                for r in reports[:10]:
                    print(f"  [{r['severity']}] {r['title']}")

    elif args.domains:
        scope_data = manual_scope(args.domains, args.exclude)
    else:
        log("err", "Provide --platform hackerone --program X or --domains 'domain.com'")
        sys.exit(1)

    if args.json:
        print(json.dumps(scope_data, indent=2))
    else:
        print_scope(scope_data)

    # Save to targets directory
    filepath = save_scope(scope_data, args.output_dir)

    # Generate ScopeChecker code snippet
    code = generate_scope_checker_config(scope_data)
    log("info", "ScopeChecker initialization code:")
    print(code)

    return scope_data


if __name__ == "__main__":
    main()
