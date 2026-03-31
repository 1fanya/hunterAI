#!/usr/bin/env python3
"""
HackerOne Program Collector — Automated Program Intelligence Gathering

Collects ALL program data from HackerOne by program handle:
- In-scope assets (domains, URLs, apps, APIs)
- Out-of-scope items
- Bounty reward table (severity → payout)
- Program rules and restrictions
- Hacktivity (disclosed reports — learn what's been found)
- Response metrics (response time, resolution time)

Uses HackerOne's GraphQL API — no browser needed.

Usage:
    python3 h1_collector.py --program rockstargames
    python3 h1_collector.py --program rockstargames --save
    python3 h1_collector.py --program rockstargames --hacktivity-only
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
TARGETS_DIR = os.path.join(BASE_DIR, "targets")

GREEN = "\033[0;32m"
RED = "\033[0;31m"
YELLOW = "\033[1;33m"
CYAN = "\033[0;36m"
BOLD = "\033[1m"
NC = "\033[0m"
DIM = "\033[2m"


def log(level, msg):
    colors = {"ok": GREEN, "err": RED, "warn": YELLOW, "info": CYAN}
    symbols = {"ok": "+", "err": "-", "warn": "!", "info": "*"}
    ts = datetime.now().strftime("%H:%M:%S")
    print(f"[{ts}] {colors.get(level, '')}{BOLD}[{symbols.get(level, '*')}]{NC} {msg}")


def h1_graphql(query, variables=None):
    """Send GraphQL request to HackerOne."""
    url = "https://hackerone.com/graphql"
    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json",
        "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0",
        "Origin": "https://hackerone.com",
        "Referer": "https://hackerone.com/",
    }

    # Add auth if available
    h1_token = os.environ.get("H1_API_TOKEN", "")
    if h1_token:
        headers["Authorization"] = f"Bearer {h1_token}"

    body = {"query": query}
    if variables:
        body["variables"] = variables

    data = json.dumps(body).encode("utf-8")
    try:
        req = Request(url, data=data, headers=headers, method="POST")
        with urlopen(req, timeout=30) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except HTTPError as e:
        body_text = ""
        try:
            body_text = e.read().decode("utf-8", errors="replace")[:2000]
        except Exception:
            pass
        log("err", f"GraphQL error {e.code}: {body_text[:200]}")
        return None
    except Exception as e:
        log("err", f"Request failed: {e}")
        return None


def h1_api_v1(endpoint):
    """Call HackerOne REST API v1 (requires API credentials)."""
    h1_user = os.environ.get("H1_API_USERNAME", "")
    h1_token = os.environ.get("H1_API_TOKEN", "")

    if not h1_user or not h1_token:
        return None

    import base64
    url = f"https://api.hackerone.com/v1/{endpoint}"
    credentials = base64.b64encode(f"{h1_user}:{h1_token}".encode()).decode()

    headers = {
        "Authorization": f"Basic {credentials}",
        "Accept": "application/json",
    }

    try:
        req = Request(url, headers=headers)
        with urlopen(req, timeout=30) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except HTTPError as e:
        if e.code == 401:
            log("warn", "H1 API auth failed — using public endpoints")
        return None
    except Exception:
        return None


class H1Collector:
    """Collects all program data from HackerOne."""

    def __init__(self, program_handle):
        self.handle = program_handle
        self.data = {
            "program": program_handle,
            "collected_at": datetime.now().isoformat(),
            "scope": {"in_scope": [], "out_of_scope": []},
            "bounty_table": [],
            "rules": "",
            "response_metrics": {},
            "hacktivity": [],
            "program_info": {},
        }

    def collect_all(self):
        """Collect all program data."""
        print(f"\n{BOLD}{'='*60}{NC}")
        print(f"{BOLD}  HackerOne Program Collector: {self.handle}{NC}")
        print(f"{'='*60}\n")

        self._collect_program_info()
        time.sleep(1)
        self._collect_scope()
        time.sleep(1)
        self._collect_hacktivity()

        return self.data

    def _collect_program_info(self):
        """Collect program info, policy, and bounty table."""
        log("info", "Fetching program info and policy...")

        # Try REST API first
        api_data = h1_api_v1(f"hackers/programs/{self.handle}")
        if api_data and "data" in api_data:
            program = api_data["data"]
            attrs = program.get("attributes", {})
            self.data["program_info"] = {
                "name": attrs.get("name", self.handle),
                "handle": attrs.get("handle", self.handle),
                "state": attrs.get("state", ""),
                "started_accepting_at": attrs.get("started_accepting_at", ""),
                "offers_bounties": attrs.get("offers_bounties", False),
                "submission_state": attrs.get("submission_state", ""),
            }
            self.data["rules"] = attrs.get("policy", "")
            log("ok", f"Got program info via API v1")

            # Extract bounty ranges from relationships
            rels = program.get("relationships", {})
            bounty_data = rels.get("structured_scopes", {}).get("data", [])
            for scope in bounty_data:
                s_attrs = scope.get("attributes", {})
                self.data["scope"]["in_scope" if s_attrs.get("eligible_for_bounty") else "out_of_scope"].append({
                    "asset": s_attrs.get("asset_identifier", ""),
                    "type": s_attrs.get("asset_type", ""),
                    "instruction": s_attrs.get("instruction", ""),
                    "eligible_for_bounty": s_attrs.get("eligible_for_bounty", False),
                    "eligible_for_submission": s_attrs.get("eligible_for_submission", True),
                    "max_severity": s_attrs.get("max_severity", ""),
                })
            if bounty_data:
                log("ok", f"Got {len(bounty_data)} scope items via API v1")
                return

        # Fallback: GraphQL for program info
        query = """
        query TeamProfilePage($handle: String!) {
          team(handle: $handle) {
            id
            handle
            name
            about
            state
            currency
            offers_bounties
            base_bounty
            submission_state
            started_accepting_at
            response_efficiency_percentage
            bug_count
            resolved_report_count
            policy
            allows_bounty_splitting
            average_bounty_lower_amount
            average_bounty_upper_amount
            top_bounty_lower_amount
            top_bounty_upper_amount
            bounty_table {
              id
              low
              medium
              high
              critical
            }
          }
        }
        """

        result = h1_graphql(query, {"handle": self.handle})
        if result and "data" in result and result["data"].get("team"):
            team = result["data"]["team"]
            self.data["program_info"] = {
                "name": team.get("name", ""),
                "handle": team.get("handle", ""),
                "state": team.get("state", ""),
                "offers_bounties": team.get("offers_bounties", False),
                "submission_state": team.get("submission_state", ""),
                "started_accepting_at": team.get("started_accepting_at", ""),
                "bug_count": team.get("bug_count", 0),
                "resolved_reports": team.get("resolved_report_count", 0),
                "response_efficiency": team.get("response_efficiency_percentage", ""),
                "avg_bounty": f"${team.get('average_bounty_lower_amount', '?')}-${team.get('average_bounty_upper_amount', '?')}",
                "top_bounty": f"${team.get('top_bounty_lower_amount', '?')}-${team.get('top_bounty_upper_amount', '?')}",
            }
            self.data["rules"] = team.get("policy", "")

            bt = team.get("bounty_table")
            if bt:
                self.data["bounty_table"] = [
                    {"severity": "low", "amount": bt.get("low", "")},
                    {"severity": "medium", "amount": bt.get("medium", "")},
                    {"severity": "high", "amount": bt.get("high", "")},
                    {"severity": "critical", "amount": bt.get("critical", "")},
                ]

            log("ok", f"Got program info via GraphQL")
        else:
            log("warn", "GraphQL program query returned no data — trying alternative")
            self._collect_program_info_alt()

    def _collect_program_info_alt(self):
        """Alternative method to get program info via directory API."""
        log("info", "Trying HackerOne directory endpoint...")
        try:
            url = f"https://hackerone.com/{self.handle}"
            headers = {
                "Accept": "application/json",
                "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0",
            }
            req = Request(url, headers=headers)
            with urlopen(req, timeout=15) as resp:
                content_type = resp.headers.get("Content-Type", "")
                body = resp.read().decode("utf-8", errors="replace")

                if "application/json" in content_type:
                    data = json.loads(body)
                    log("ok", "Got JSON response from program page")
                    self.data["program_info"]["raw"] = data
                else:
                    # Parse HTML for embedded JSON
                    json_match = re.search(r'__NEXT_DATA__\s*=\s*({.+?})\s*</script>', body)
                    if json_match:
                        try:
                            next_data = json.loads(json_match.group(1))
                            log("ok", "Extracted embedded JSON data")
                            self.data["program_info"]["raw_next"] = next_data
                        except json.JSONDecodeError:
                            pass

                    # Extract any scope info from HTML
                    scope_matches = re.findall(
                        r'(?:asset_identifier|eligible_for_bounty|asset_type)["\s:]+["\s]*([^"<]+)',
                        body,
                    )
                    if scope_matches:
                        log("info", f"Found {len(scope_matches)} scope references in HTML")

        except Exception as e:
            log("warn", f"Alternative fetch failed: {e}")

    def _collect_scope(self):
        """Collect structured scope (in-scope and out-of-scope assets)."""
        if self.data["scope"]["in_scope"]:
            return  # Already got scope from API v1

        log("info", "Fetching scope via GraphQL...")

        query = """
        query TeamAssets($handle: String!, $first: Int, $cursor: String) {
          team(handle: $handle) {
            structured_scopes(first: $first, after: $cursor, archived: false) {
              edges {
                node {
                  id
                  asset_identifier
                  asset_type
                  instruction
                  eligible_for_bounty
                  eligible_for_submission
                  max_severity
                  created_at
                }
              }
              pageInfo {
                hasNextPage
                endCursor  
              }
            }
          }
        }
        """

        cursor = None
        all_scopes = []

        while True:
            variables = {"handle": self.handle, "first": 100}
            if cursor:
                variables["cursor"] = cursor

            result = h1_graphql(query, variables)
            if not result or "data" not in result:
                break

            team = result["data"].get("team")
            if not team:
                log("warn", "No team data in scope response")
                break

            scopes = team.get("structured_scopes", {})
            edges = scopes.get("edges", [])

            for edge in edges:
                node = edge.get("node", {})
                scope_item = {
                    "asset": node.get("asset_identifier", ""),
                    "type": node.get("asset_type", ""),
                    "instruction": node.get("instruction", ""),
                    "eligible_for_bounty": node.get("eligible_for_bounty", False),
                    "eligible_for_submission": node.get("eligible_for_submission", True),
                    "max_severity": node.get("max_severity", ""),
                }
                all_scopes.append(scope_item)

                if scope_item["eligible_for_submission"]:
                    self.data["scope"]["in_scope"].append(scope_item)
                else:
                    self.data["scope"]["out_of_scope"].append(scope_item)

            page_info = scopes.get("pageInfo", {})
            if page_info.get("hasNextPage"):
                cursor = page_info.get("endCursor")
                time.sleep(0.5)
            else:
                break

        if all_scopes:
            log("ok", f"Got {len(all_scopes)} scope items "
                f"({len(self.data['scope']['in_scope'])} in-scope, "
                f"{len(self.data['scope']['out_of_scope'])} out-of-scope)")
        else:
            log("warn", "No scope items returned — program may require auth or be private")
            self._collect_scope_fallback()

    def _collect_scope_fallback(self):
        """Fallback scope collection via web search/known data."""
        log("info", "Attempting scope collection via known patterns...")

        # For well-known programs, we can check common domain patterns
        common_patterns = {
            "rockstargames": {
                "domains": [
                    "*.rockstargames.com",
                    "socialclub.rockstargames.com",
                    "support.rockstargames.com",
                    "www.rockstargames.com",
                ],
                "note": "Verify against actual H1 scope before testing",
            }
        }

        if self.handle in common_patterns:
            pattern = common_patterns[self.handle]
            for domain in pattern["domains"]:
                self.data["scope"]["in_scope"].append({
                    "asset": domain,
                    "type": "URL",
                    "instruction": pattern.get("note", ""),
                    "eligible_for_bounty": True,
                    "source": "known_pattern_VERIFY_ON_H1",
                })
            log("warn", f"Added {len(pattern['domains'])} known domains — MUST VERIFY on H1 page!")

    def _collect_hacktivity(self):
        """Collect disclosed reports from Hacktivity."""
        log("info", "Fetching Hacktivity (disclosed reports)...")

        query = """
        query HacktivityPageQuery($handle: String!, $first: Int, $cursor: String) {
          team(handle: $handle) {
            hacktivity_items(first: $first, after: $cursor, 
              filter: {disclosed: true}) {
              edges {
                node {
                  ... on Disclosed {
                    id
                    title: report_title
                    severity_rating
                    disclosed_at
                    upvoted: vote_count
                    bounty_amount
                    report {
                      substate
                      weakness {
                        name
                      }
                    }
                  }
                }
              }
              pageInfo {
                hasNextPage
                endCursor
              }
            }
          }
        }
        """

        cursor = None
        all_reports = []

        for page in range(3):  # Max 3 pages = 75 reports
            variables = {"handle": self.handle, "first": 25}
            if cursor:
                variables["cursor"] = cursor

            result = h1_graphql(query, variables)
            if not result or "data" not in result:
                break

            team = result["data"].get("team")
            if not team:
                break

            items = team.get("hacktivity_items", {})
            edges = items.get("edges", [])

            for edge in edges:
                node = edge.get("node", {})
                if not node or not node.get("title"):
                    continue

                report = node.get("report", {}) or {}
                weakness = report.get("weakness", {}) or {}

                all_reports.append({
                    "title": node.get("title", ""),
                    "severity": node.get("severity_rating", ""),
                    "bounty": node.get("bounty_amount", ""),
                    "disclosed_at": node.get("disclosed_at", ""),
                    "votes": node.get("upvoted", 0),
                    "weakness": weakness.get("name", ""),
                    "substate": report.get("substate", ""),
                })

            page_info = items.get("pageInfo", {})
            if page_info.get("hasNextPage"):
                cursor = page_info.get("endCursor")
                time.sleep(1)
            else:
                break

        self.data["hacktivity"] = all_reports
        if all_reports:
            log("ok", f"Got {len(all_reports)} disclosed reports from Hacktivity")
        else:
            log("warn", "No Hacktivity data — program may have no disclosed reports")

    def print_report(self):
        """Print comprehensive program report."""
        info = self.data["program_info"]
        scope = self.data["scope"]
        bounty = self.data["bounty_table"]
        hacktivity = self.data["hacktivity"]

        print(f"\n{BOLD}{'═'*60}{NC}")
        print(f"{BOLD}  PROGRAM: {info.get('name', self.handle)}{NC}")
        print(f"{BOLD}{'═'*60}{NC}\n")

        # Program info
        print(f"  Handle:      {info.get('handle', self.handle)}")
        print(f"  State:       {info.get('state', 'unknown')}")
        print(f"  Bounties:    {'Yes' if info.get('offers_bounties') else 'No'}")
        print(f"  Submissions: {info.get('submission_state', 'unknown')}")
        if info.get("avg_bounty"):
            print(f"  Avg Bounty:  {info['avg_bounty']}")
        if info.get("top_bounty"):
            print(f"  Top Bounty:  {info['top_bounty']}")
        if info.get("resolved_reports"):
            print(f"  Resolved:    {info['resolved_reports']} reports")
        if info.get("response_efficiency"):
            print(f"  Response:    {info['response_efficiency']}% efficiency")

        # Bounty table
        if bounty:
            print(f"\n  {CYAN}Bounty Table:{NC}")
            for b in bounty:
                print(f"    {b['severity']:12s} → ${b['amount']}")

        # In-scope assets
        if scope["in_scope"]:
            print(f"\n  {GREEN}In-Scope Assets ({len(scope['in_scope'])}):{NC}")
            for s in scope["in_scope"]:
                bounty_tag = " 💰" if s.get("eligible_for_bounty") else ""
                print(f"    [{s.get('type', '?'):10s}] {s['asset']}{bounty_tag}")
                if s.get("instruction"):
                    # Show first 100 chars of instruction
                    inst = s["instruction"].replace("\n", " ").strip()[:100]
                    print(f"    {DIM}           → {inst}{NC}")

        # Out-of-scope
        if scope["out_of_scope"]:
            print(f"\n  {RED}Out-of-Scope ({len(scope['out_of_scope'])}):{NC}")
            for s in scope["out_of_scope"]:
                print(f"    [{s.get('type', '?'):10s}] {s['asset']}")

        # Program rules (truncated)
        if self.data["rules"]:
            rules = self.data["rules"]
            print(f"\n  {YELLOW}Program Rules (first 500 chars):{NC}")
            print(f"    {rules[:500].replace(chr(10), chr(10) + '    ')}")
            if len(rules) > 500:
                print(f"    ... ({len(rules)} chars total)")

        # Hacktivity
        if hacktivity:
            print(f"\n  {CYAN}Hacktivity — Disclosed Reports ({len(hacktivity)}):{NC}")
            for i, r in enumerate(hacktivity[:20], 1):
                sev_colors = {"critical": RED, "high": RED, "medium": YELLOW, "low": GREEN}
                sev = r.get("severity", "unknown")
                color = sev_colors.get(sev, "")
                bounty_str = f" (${r['bounty']})" if r.get("bounty") else ""
                weakness = f" [{r['weakness']}]" if r.get("weakness") else ""
                print(f"    {i:2d}. {color}[{sev:8s}]{NC} {r['title'][:65]}{bounty_str}{weakness}")

        # Hunt recommendations
        print(f"\n  {BOLD}Hunt Recommendations:{NC}")
        self._print_recommendations()

        print(f"\n{'═'*60}\n")

    def _print_recommendations(self):
        """Generate hunt recommendations from Hacktivity patterns."""
        hacktivity = self.data["hacktivity"]
        scope = self.data["scope"]["in_scope"]

        # Count vuln types from Hacktivity
        vuln_counts = {}
        for r in hacktivity:
            weakness = r.get("weakness", "Other")
            if weakness:
                vuln_counts[weakness] = vuln_counts.get(weakness, 0) + 1

        if vuln_counts:
            # Most common = most likely accepted, but also most likely duped
            most_common = sorted(vuln_counts.items(), key=lambda x: x[1], reverse=True)
            print(f"    {YELLOW}Common findings (high dup risk):{NC}")
            for vuln, count in most_common[:5]:
                print(f"      {vuln}: {count} reports")

            print(f"    {GREEN}Recommended (less explored):{NC}")
            less_tested = [
                "Race Condition", "HTTP Request Smuggling", "SSRF",
                "Business Logic", "JWT", "GraphQL",
                "Subdomain Takeover", "CORS Misconfiguration",
            ]
            for vuln in less_tested:
                if vuln not in vuln_counts:
                    print(f"      → {vuln} (0 disclosed — untested territory)")

        # Scope-based recommendations
        domains = [s["asset"] for s in scope if s.get("type") in ("URL", "DOMAIN", "WILDCARD")]
        if domains:
            print(f"    {CYAN}Target domains:{NC}")
            for d in domains[:10]:
                print(f"      → {d}")

    def save(self):
        """Save collected data."""
        os.makedirs(TARGETS_DIR, exist_ok=True)
        filepath = os.path.join(TARGETS_DIR, f"{self.handle}.json")
        with open(filepath, "w") as f:
            json.dump(self.data, f, indent=2)
        log("ok", f"Saved to {filepath}")

        # Also save scope as a simple text file for other tools
        scope_file = os.path.join(TARGETS_DIR, f"{self.handle}_scope.txt")
        with open(scope_file, "w") as f:
            f.write(f"# In-scope assets for {self.handle}\n")
            f.write(f"# Collected: {self.data['collected_at']}\n\n")
            for s in self.data["scope"]["in_scope"]:
                f.write(f"{s['asset']}\n")
            f.write(f"\n# Out-of-scope\n")
            for s in self.data["scope"]["out_of_scope"]:
                f.write(f"!{s['asset']}\n")
        log("ok", f"Scope file saved to {scope_file}")

        # Save Hacktivity as text for dedup reference
        if self.data["hacktivity"]:
            hacktivity_file = os.path.join(TARGETS_DIR, f"{self.handle}_hacktivity.txt")
            with open(hacktivity_file, "w") as f:
                f.write(f"# Hacktivity for {self.handle}\n\n")
                for r in self.data["hacktivity"]:
                    f.write(f"[{r.get('severity', '?')}] {r.get('title', '?')}")
                    if r.get("weakness"):
                        f.write(f" [{r['weakness']}]")
                    if r.get("bounty"):
                        f.write(f" (${r['bounty']})")
                    f.write("\n")
            log("ok", f"Hacktivity saved to {hacktivity_file}")

        return filepath


def main():
    parser = argparse.ArgumentParser(description="HackerOne Program Collector")
    parser.add_argument("--program", required=True, help="H1 program handle (e.g. rockstargames)")
    parser.add_argument("--save", action="store_true", help="Save collected data to targets/")
    parser.add_argument("--json", action="store_true", help="JSON output only")
    parser.add_argument("--hacktivity-only", action="store_true", help="Only fetch Hacktivity")
    args = parser.parse_args()

    collector = H1Collector(args.program)

    if args.hacktivity_only:
        collector._collect_hacktivity()
    else:
        collector.collect_all()

    if args.json:
        print(json.dumps(collector.data, indent=2))
    else:
        collector.print_report()

    if args.save or not args.json:
        collector.save()


if __name__ == "__main__":
    main()
