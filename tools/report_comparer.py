#!/usr/bin/env python3
"""
Report Comparer — Dedup findings against HackerOne Hacktivity

Before submitting a report, checks for similar disclosed reports on the program
to avoid duplicates. Also checks against known "always rejected" patterns.

Usage:
    python3 report_comparer.py --program shopify --finding "IDOR on /api/users/{id}"
    python3 report_comparer.py --program shopify --finding-file findings/target/verified_exploits.json
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


# Always-rejected patterns — don't waste time submitting these
ALWAYS_REJECTED = [
    "missing csp header",
    "missing hsts header",
    "missing security headers",
    "missing x-frame-options",
    "missing x-content-type-options",
    "missing spf record",
    "missing dkim",
    "missing dmarc",
    "graphql introspection enabled",
    "graphql introspection",
    "banner disclosure",
    "version disclosure",
    "server version",
    "clickjacking on non-sensitive",
    "tabnabbing",
    "csv injection",
    "cors wildcard without credential",
    "logout csrf",
    "self-xss",
    "open redirect alone",
    "open redirect without chain",
    "oauth client_secret in mobile",
    "ssrf dns only",
    "ssrf dns-only",
    "ssrf dns callback only",
    "host header injection alone",
    "no rate limit on non-critical",
    "session not invalidated on logout",
    "concurrent sessions allowed",
    "internal ip disclosure",
    "mixed content",
    "ssl weak cipher",
    "missing httponly flag alone",
    "missing secure flag alone",
    "broken external links",
    "pre-account takeover",
    "autocomplete on password",
    "email verification bypass",
    "username enumeration via timing",
]


def fetch_hacktivity(program_handle, limit=50):
    """Fetch disclosed reports for a program from HackerOne."""
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
              vulnerability_information
            }
          }
        }
      }
    }
    """ % (limit, program_handle)

    headers = {"Content-Type": "application/json"}
    api_token = os.environ.get("H1_API_TOKEN", "")
    if api_token:
        headers["Authorization"] = f"Bearer {api_token}"

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
        if report and report.get("title"):
            reports.append({
                "title": report.get("title", ""),
                "severity": report.get("severity_rating", ""),
                "state": report.get("substate", ""),
                "disclosed_at": report.get("disclosed_at", ""),
                "info": report.get("vulnerability_information", ""),
            })
    return reports


def normalize(text):
    """Normalize text for comparison."""
    return re.sub(r'[^a-z0-9\s]', '', text.lower()).strip()


def calculate_similarity(finding_title, report_title):
    """Calculate word-overlap similarity between two titles."""
    words_a = set(normalize(finding_title).split())
    words_b = set(normalize(report_title).split())

    if not words_a or not words_b:
        return 0.0

    intersection = words_a & words_b
    union = words_a | words_b

    # Jaccard similarity
    jaccard = len(intersection) / len(union) if union else 0

    # Also check for vuln class keyword overlap
    vuln_keywords = {"idor", "ssrf", "xss", "sqli", "sql", "injection", "bypass",
                     "race", "csrf", "ssti", "rce", "lfi", "rfi", "xxe",
                     "takeover", "redirect", "cors", "smuggling", "poisoning",
                     "ato", "oauth", "saml", "jwt", "graphql", "upload"}

    keywords_a = words_a & vuln_keywords
    keywords_b = words_b & vuln_keywords
    keyword_overlap = keywords_a & keywords_b

    # Boost similarity if same vuln class
    if keyword_overlap:
        jaccard = min(1.0, jaccard + 0.2 * len(keyword_overlap))

    return round(jaccard, 3)


def check_always_rejected(finding_title):
    """Check if finding matches always-rejected patterns."""
    normalized = normalize(finding_title)
    matches = []
    for pattern in ALWAYS_REJECTED:
        if pattern in normalized:
            matches.append(pattern)
    return matches


def compare_finding(finding_title, program_handle=None, hacktivity=None):
    """Compare a finding against Hacktivity and rejection list.

    Returns:
        dict with: verdict (submit/duplicate/rejected/chain_required),
        similar_reports, rejection_matches, recommendation
    """
    result = {
        "finding": finding_title,
        "verdict": "submit",
        "similar_reports": [],
        "rejection_matches": [],
        "recommendation": "",
    }

    # Check 1: Always-rejected list
    rejection_matches = check_always_rejected(finding_title)
    if rejection_matches:
        result["verdict"] = "rejected"
        result["rejection_matches"] = rejection_matches
        result["recommendation"] = (
            f"This finding matches always-rejected pattern(s): {', '.join(rejection_matches)}. "
            f"DO NOT SUBMIT unless you can chain it to a higher-impact vulnerability."
        )
        return result

    # Check 2: Hacktivity dedup
    if hacktivity is None and program_handle:
        log("info", f"Fetching Hacktivity for {program_handle}...")
        hacktivity = fetch_hacktivity(program_handle)

    if hacktivity:
        for report in hacktivity:
            similarity = calculate_similarity(finding_title, report["title"])
            if similarity > 0.3:
                result["similar_reports"].append({
                    "title": report["title"],
                    "severity": report["severity"],
                    "similarity": similarity,
                    "disclosed_at": report.get("disclosed_at", ""),
                })

        # Sort by similarity
        result["similar_reports"].sort(key=lambda x: x["similarity"], reverse=True)

        # Determine verdict
        if result["similar_reports"]:
            top_sim = result["similar_reports"][0]["similarity"]
            if top_sim > 0.7:
                result["verdict"] = "likely_duplicate"
                result["recommendation"] = (
                    f"HIGH duplicate risk ({top_sim:.0%} similar). "
                    f"Most similar: '{result['similar_reports'][0]['title']}'. "
                    f"Consider: is your finding in a different endpoint? Different impact? "
                    f"If so, emphasize the difference in your report."
                )
            elif top_sim > 0.5:
                result["verdict"] = "possible_duplicate"
                result["recommendation"] = (
                    f"MODERATE duplicate risk ({top_sim:.0%} similar). "
                    f"Similar report exists. Make sure your PoC shows a DIFFERENT endpoint "
                    f"or a NEW attack vector not covered in the existing report."
                )
            else:
                result["verdict"] = "submit"
                result["recommendation"] = (
                    f"LOW duplicate risk. Some related reports exist but your finding "
                    f"appears to be distinct. Submit with confidence."
                )
        else:
            result["verdict"] = "submit"
            result["recommendation"] = "No similar reports found. Likely unique. Submit."

    return result


def print_comparison(result):
    """Pretty-print comparison results."""
    print(f"\n{BOLD}{'='*60}{NC}")
    print(f"{BOLD}  Dedup Check: {result['finding'][:50]}{NC}")
    print(f"{BOLD}{'='*60}{NC}\n")

    # Verdict
    verdict_colors = {
        "submit": GREEN,
        "likely_duplicate": RED,
        "possible_duplicate": YELLOW,
        "rejected": RED,
        "chain_required": YELLOW,
    }
    color = verdict_colors.get(result["verdict"], NC)
    print(f"  Verdict: {color}{BOLD}{result['verdict'].upper()}{NC}")
    print(f"  {result['recommendation']}")

    # Rejection matches
    if result["rejection_matches"]:
        print(f"\n  {RED}Matches always-rejected patterns:{NC}")
        for pattern in result["rejection_matches"]:
            print(f"    ✗ {pattern}")

    # Similar reports
    if result["similar_reports"]:
        print(f"\n  {CYAN}Similar disclosed reports:{NC}")
        for i, report in enumerate(result["similar_reports"][:5], 1):
            sim_pct = f"{report['similarity']:.0%}"
            sev = report.get("severity", "?")
            print(f"    {i}. [{sev}] {report['title']} ({sim_pct} match)")
            if report.get("disclosed_at"):
                print(f"       Disclosed: {report['disclosed_at'][:10]}")

    print(f"\n{'='*60}\n")


def main():
    parser = argparse.ArgumentParser(description="Report Dedup Checker")
    parser.add_argument("--program", help="HackerOne program handle")
    parser.add_argument("--finding", help="Finding title/description to check")
    parser.add_argument("--finding-file", help="JSON file with findings to check")
    parser.add_argument("--json", action="store_true", help="Output JSON")
    args = parser.parse_args()

    if args.finding_file:
        with open(args.finding_file) as f:
            data = json.load(f)
        findings = data.get("verified", data.get("findings", []))

        # Fetch Hacktivity once
        hacktivity = None
        if args.program:
            hacktivity = fetch_hacktivity(args.program)

        all_results = []
        for finding in findings:
            title = finding.get("impact", finding.get("type", "unknown"))
            result = compare_finding(title, hacktivity=hacktivity)
            all_results.append(result)
            if not args.json:
                print_comparison(result)

        if args.json:
            print(json.dumps(all_results, indent=2))

    elif args.finding:
        result = compare_finding(args.finding, program_handle=args.program)
        if args.json:
            print(json.dumps(result, indent=2))
        else:
            print_comparison(result)
    else:
        log("err", "Provide --finding or --finding-file")
        sys.exit(1)


if __name__ == "__main__":
    main()
