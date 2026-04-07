#!/usr/bin/env python3
"""
h1_api.py — HackerOne API Integration

Fetch program scope, search Hacktivity for duplicates, get bounty stats.

Usage:
    from h1_api import HackerOneAPI
    h1 = HackerOneAPI()
    scope = h1.get_scope("rockstargames")
    dupes = h1.search_hacktivity("IDOR", "rockstargames")
"""
import json
import os
import time
from pathlib import Path

try:
    import requests
except ImportError:
    requests = None

H1_API = "https://api.hackerone.com/v1"
H1_GRAPHQL = "https://hackerone.com/graphql"


class HackerOneAPI:
    """HackerOne API client for scope, hacktivity, and program intel."""

    def __init__(self, api_token: str = ""):
        self.token = api_token or os.environ.get("H1_API_TOKEN", "")
        self.session = requests.Session() if requests else None
        if self.session:
            self.session.headers["User-Agent"] = "HunterAI/1.0"
            self.session.headers["Accept"] = "application/json"
            if self.token:
                self.session.headers["Authorization"] = f"Bearer {self.token}"

    def get_program(self, handle: str) -> dict:
        """Get program details by handle."""
        try:
            resp = self.session.get(
                f"{H1_API}/hackers/programs/{handle}",
                timeout=15)
            if resp.status_code == 200:
                return resp.json().get("data", {}).get("attributes", {})
            return {"error": f"HTTP {resp.status_code}"}
        except Exception as e:
            return {"error": str(e)}

    def get_scope(self, handle: str) -> dict:
        """Get program scope (in-scope and out-of-scope assets)."""
        try:
            resp = self.session.get(
                f"{H1_API}/hackers/programs/{handle}/structured_scopes",
                params={"page[size]": 100},
                timeout=15)
            if resp.status_code != 200:
                return {"error": f"HTTP {resp.status_code}"}

            data = resp.json()
            in_scope = []
            out_scope = []

            for item in data.get("data", []):
                attrs = item.get("attributes", {})
                entry = {
                    "asset": attrs.get("asset_identifier", ""),
                    "type": attrs.get("asset_type", ""),
                    "instruction": attrs.get("instruction", ""),
                    "eligible": attrs.get("eligible_for_bounty", False),
                    "max_severity": attrs.get("max_severity", ""),
                }
                if attrs.get("eligible_for_submission"):
                    in_scope.append(entry)
                else:
                    out_scope.append(entry)

            return {"in_scope": in_scope, "out_of_scope": out_scope}
        except Exception as e:
            return {"error": str(e)}

    def search_hacktivity(self, query: str, program: str = "") -> list:
        """Search Hacktivity for disclosed reports (dedup check)."""
        try:
            gql_query = {
                "operationName": "HacktivitySearchQuery",
                "variables": {
                    "queryString": f"{query} {program}".strip(),
                    "size": 25,
                    "from": 0,
                },
                "query": """query HacktivitySearchQuery($queryString: String!, $size: Int, $from: Int) {
                    search(index: CompleteHacktivityReportIndexService, query_string: $queryString,
                           size: $size, from: $from) {
                        nodes {
                            ... on HacktivityDocument {
                                report { title, substate, severity_rating, bounty_amount,
                                         created_at, disclosed_at,
                                         team { handle, name } }
                            }
                        }
                    }
                }"""
            }

            resp = self.session.post(H1_GRAPHQL, json=gql_query, timeout=15)
            if resp.status_code != 200:
                return [{"error": f"HTTP {resp.status_code}"}]

            results = []
            for node in resp.json().get("data", {}).get("search", {}).get("nodes", []):
                report = node.get("report", {})
                if report:
                    results.append({
                        "title": report.get("title", ""),
                        "severity": report.get("severity_rating", ""),
                        "bounty": report.get("bounty_amount", ""),
                        "program": report.get("team", {}).get("handle", ""),
                        "disclosed": report.get("disclosed_at", ""),
                    })
            return results
        except Exception as e:
            return [{"error": str(e)}]

    def check_duplicate(self, vuln_class: str, endpoint: str,
                        program: str) -> dict:
        """Check if a finding is likely a duplicate in Hacktivity."""
        reports = self.search_hacktivity(f"{vuln_class} {endpoint}", program)
        clean = [r for r in reports if not r.get("error")]

        is_dupe = False
        matches = []
        for r in clean:
            title = r.get("title", "").lower()
            if (vuln_class.lower() in title and
                    (endpoint.lower() in title or
                     endpoint.split("/")[-1].lower() in title)):
                is_dupe = True
                matches.append(r)

        return {
            "likely_duplicate": is_dupe,
            "matching_reports": matches,
            "total_similar": len(clean),
            "reports": clean[:10],
        }

    def get_bounty_range(self, handle: str) -> dict:
        """Get bounty ranges for a program."""
        program = self.get_program(handle)
        if "error" in program:
            return program
        return {
            "handle": handle,
            "offers_bounties": program.get("offers_bounties", False),
            "response_efficiency": program.get("response_efficiency_percentage", 0),
        }
