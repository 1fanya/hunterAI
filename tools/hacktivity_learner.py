#!/usr/bin/env python3
"""
Hacktivity Learner — Self-learning engine that reads HackerOne disclosed reports
and extracts attack patterns, techniques, and bypass methods.

Teaches Claude Code new attack techniques by:
1. Reading disclosed reports from H1 Hacktivity API
2. Extracting vulnerability patterns, payloads, and bypass techniques
3. Saving learned patterns to skills/learned/ for future hunts
4. Building a knowledge graph of vuln_class → technique → tech_stack

Usage:
    python3 hacktivity_learner.py --program uber --count 50
    python3 hacktivity_learner.py --top-reports --severity critical,high
    python3 hacktivity_learner.py --search "ssrf bypass" --count 20
    python3 hacktivity_learner.py --learn-all  # learn from all saved reports
"""

import argparse
import json
import os
import re
import sys
import time
from datetime import datetime, timezone

try:
    import urllib.request
    import urllib.error
except ImportError:
    pass

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LEARNED_DIR = os.path.join(BASE_DIR, "skills", "learned")
REPORTS_CACHE = os.path.join(BASE_DIR, "hunt-memory", "hacktivity_cache")

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

# Vuln class classification patterns
VULN_PATTERNS = {
    "idor": re.compile(r'\b(idor|insecure direct|broken object|bola|unauthorized.*access.*other.*user)', re.I),
    "ssrf": re.compile(r'\b(ssrf|server.side.*request|internal.*service.*access|metadata.*169\.254)', re.I),
    "xss": re.compile(r'\b(xss|cross.site.*script|stored.*xss|reflected.*xss|dom.*xss)', re.I),
    "sqli": re.compile(r'\b(sqli|sql.*inject|union.*select|blind.*sql|time.based)', re.I),
    "rce": re.compile(r'\b(rce|remote.*code.*exec|command.*inject|os.*command|shell.*inject)', re.I),
    "ssti": re.compile(r'\b(ssti|server.side.*template|template.*inject|jinja|twig|freemarker)', re.I),
    "auth_bypass": re.compile(r'\b(auth.*bypass|broken.*auth|privilege.*escalat|access.*control)', re.I),
    "race_condition": re.compile(r'\b(race.*condition|toctou|double.*spend|concurrent)', re.I),
    "business_logic": re.compile(r'\b(business.*logic|price.*manipul|workflow.*bypass|logic.*flaw)', re.I),
    "info_disclosure": re.compile(r'\b(information.*disclos|sensitive.*data.*expos|leak.*credentials)', re.I),
    "cors": re.compile(r'\b(cors|cross.origin|origin.*misconfig)', re.I),
    "csrf": re.compile(r'\b(csrf|cross.site.*request.*forg)', re.I),
    "cache_poisoning": re.compile(r'\b(cache.*poison|web.*cache.*decept|cache.*deception)', re.I),
    "http_smuggling": re.compile(r'\b(http.*smuggl|request.*smuggl|cl\.te|te\.cl|desync)', re.I),
    "open_redirect": re.compile(r'\b(open.*redirect|url.*redirect|redirect.*bypass)', re.I),
    "xxe": re.compile(r'\b(xxe|xml.*external.*entit|xml.*inject)', re.I),
}

# Technique extraction patterns
TECHNIQUE_PATTERNS = [
    re.compile(r'(?:payload|poc|exploit|bypass)(?:\s*[:=]\s*|\s+is\s+|\s+was\s+)[`"\']([^`"\']{10,200})[`"\']', re.I),
    re.compile(r'```(?:http|bash|curl|python)?\n(.*?)```', re.S),
    re.compile(r'curl\s+["\']?https?://[^\s]+', re.I),
    re.compile(r'(?:GET|POST|PUT|DELETE|PATCH)\s+/[^\s]+', re.I),
]


class HacktivityLearner:
    """Learn attack techniques from HackerOne Hacktivity."""

    def __init__(self):
        os.makedirs(LEARNED_DIR, exist_ok=True)
        os.makedirs(REPORTS_CACHE, exist_ok=True)
        self.learned_patterns = []
        self.h1_token = os.environ.get("H1_API_TOKEN", "")

    def _h1_api(self, endpoint, params=None):
        """Call HackerOne API."""
        base = "https://api.hackerone.com/v1"
        url = f"{base}/{endpoint}"
        if params:
            from urllib.parse import urlencode
            url += "?" + urlencode(params)

        req = urllib.request.Request(url)
        req.add_header("Accept", "application/json")
        if self.h1_token:
            req.add_header("Authorization", f"Bearer {self.h1_token}")

        try:
            resp = urllib.request.urlopen(req, timeout=30)
            return json.loads(resp.read().decode())
        except Exception as e:
            log("err", f"H1 API error: {e}")
            return None

    def fetch_hacktivity(self, program=None, severity=None, count=25):
        """Fetch disclosed reports from HackerOne Hacktivity.

        Uses the public Hacktivity feed (no auth needed for disclosed reports).
        """
        log("info", f"Fetching Hacktivity reports (count={count})")

        # Use Hacktivity GraphQL-like endpoint (public)
        url = "https://hackerone.com/graphql"
        query = {
            "operationName": "HacktivityPageQuery",
            "variables": {
                "querystring": program or "",
                "where": {"report": {"disclosed_at": {"_is_null": False}}},
                "orderBy": {"field": "popular", "direction": "DESC"},
                "count": min(count, 25),
            },
            "query": """query HacktivityPageQuery($querystring: String, $orderBy: HacktivityItemOrderInput, $count: Int) {
                hacktivity_items(first: $count, query: $querystring, order_by: $orderBy) {
                    edges { node { ... on HacktivityItemInterface {
                        id report { id title severity_rating
                            substate weakness { name }
                            team { handle name }
                            disclosed_at bounty_awarded_amount
                        }
                    }}}
                }
            }"""
        }

        try:
            data = json.dumps(query).encode()
            req = urllib.request.Request(url, data=data, method="POST")
            req.add_header("Content-Type", "application/json")
            req.add_header("User-Agent", "Mozilla/5.0")
            resp = urllib.request.urlopen(req, timeout=30)
            result = json.loads(resp.read().decode())

            items = result.get("data", {}).get("hacktivity_items", {}).get("edges", [])
            reports = []
            for edge in items:
                node = edge.get("node", {})
                report = node.get("report", {})
                if report:
                    reports.append({
                        "id": report.get("id"),
                        "title": report.get("title", ""),
                        "severity": report.get("severity_rating", ""),
                        "program": report.get("team", {}).get("handle", ""),
                        "weakness": report.get("weakness", {}).get("name", ""),
                        "bounty": report.get("bounty_awarded_amount"),
                        "disclosed_at": report.get("disclosed_at"),
                    })

            log("ok", f"Fetched {len(reports)} disclosed reports")
            return reports

        except Exception as e:
            log("warn", f"GraphQL fetch failed ({e}), falling back to scrape")
            return self._scrape_hacktivity(program, count)

    def _scrape_hacktivity(self, program=None, count=25):
        """Fallback: scrape Hacktivity from public page."""
        reports = []
        url = "https://hackerone.com/hacktivity/overview"
        if program:
            url = f"https://hackerone.com/{program}/hacktivity"

        try:
            req = urllib.request.Request(url)
            req.add_header("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) Chrome/120.0.0.0")
            resp = urllib.request.urlopen(req, timeout=15)
            body = resp.read().decode("utf-8", errors="replace")

            # Extract report titles and IDs from HTML
            for match in re.finditer(r'/reports/(\d+)"[^>]*>([^<]+)', body):
                reports.append({
                    "id": match.group(1),
                    "title": match.group(2).strip(),
                    "severity": "",
                    "program": program or "unknown",
                })
                if len(reports) >= count:
                    break

        except Exception as e:
            log("err", f"Scrape failed: {e}")

        return reports

    def classify_report(self, report):
        """Classify a report into vuln classes and extract techniques."""
        title = report.get("title", "")
        weakness = report.get("weakness", "")
        combined = f"{title} {weakness}"

        vuln_classes = []
        for vc, pattern in VULN_PATTERNS.items():
            if pattern.search(combined):
                vuln_classes.append(vc)

        if not vuln_classes:
            vuln_classes = ["unknown"]

        return {
            **report,
            "vuln_classes": vuln_classes,
            "primary_class": vuln_classes[0],
        }

    def learn_from_reports(self, reports):
        """Extract patterns from reports and save as learned skills."""
        log("info", f"Learning from {len(reports)} reports")

        # Classify all reports
        classified = [self.classify_report(r) for r in reports]

        # Group by vuln class
        by_class = {}
        for r in classified:
            vc = r["primary_class"]
            by_class.setdefault(vc, []).append(r)

        # Build knowledge entries
        knowledge = {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "total_reports": len(reports),
            "vuln_classes": {},
        }

        for vc, vc_reports in by_class.items():
            # Sort by bounty (highest first)
            vc_reports.sort(key=lambda r: r.get("bounty") or 0, reverse=True)

            top_titles = [r["title"] for r in vc_reports[:10]]
            programs = list({r["program"] for r in vc_reports})
            avg_bounty = sum(r.get("bounty") or 0 for r in vc_reports) / max(len(vc_reports), 1)

            knowledge["vuln_classes"][vc] = {
                "count": len(vc_reports),
                "avg_bounty": round(avg_bounty, 2),
                "programs_affected": programs[:20],
                "top_reports": top_titles,
                "techniques_used": [r.get("weakness", "") for r in vc_reports if r.get("weakness")],
            }

        # Save knowledge
        knowledge_file = os.path.join(LEARNED_DIR, "hacktivity_knowledge.json")
        with open(knowledge_file, "w") as f:
            json.dump(knowledge, f, indent=2)
        log("ok", f"Saved knowledge to {knowledge_file}")

        # Generate SKILL.md additions
        self._generate_skill_additions(knowledge)

        return knowledge

    def _generate_skill_additions(self, knowledge):
        """Generate skill additions from learned patterns."""
        lines = [
            "# Learned Attack Patterns (Auto-Generated from Hacktivity)",
            f"\nGenerated: {knowledge['generated_at']}",
            f"Source: {knowledge['total_reports']} disclosed reports\n",
            "## Vulnerability Class Frequency (from real bounty reports)\n",
        ]

        # Sort by count
        sorted_classes = sorted(
            knowledge["vuln_classes"].items(),
            key=lambda x: x[1]["count"], reverse=True
        )

        for vc, data in sorted_classes:
            avg_b = data["avg_bounty"]
            bounty_str = f"${avg_b:.0f}" if avg_b > 0 else "N/A"
            lines.append(f"### {vc.upper()} ({data['count']} reports, avg bounty: {bounty_str})")
            lines.append(f"Programs: {', '.join(data['programs_affected'][:5])}")

            if data["top_reports"]:
                lines.append("\nTop reports to study:")
                for title in data["top_reports"][:5]:
                    lines.append(f"  - {title}")

            if data["techniques_used"]:
                unique_techniques = list(dict.fromkeys(data["techniques_used"]))[:5]
                lines.append(f"\nTechniques: {', '.join(unique_techniques)}")

            lines.append("")

        # Prioritization advice
        lines.extend([
            "## Hunt Priority Order (by ROI)\n",
            "Based on disclosed report frequency and bounty amounts:\n",
        ])

        for i, (vc, data) in enumerate(sorted_classes[:10], 1):
            avg_b = data["avg_bounty"]
            lines.append(f"{i}. **{vc}** — {data['count']} reports, avg ${avg_b:.0f}")

        skill_file = os.path.join(LEARNED_DIR, "learned_patterns.md")
        with open(skill_file, "w") as f:
            f.write("\n".join(lines))
        log("ok", f"Generated skill additions: {skill_file}")

    def learn_program(self, program, count=50):
        """Learn from a specific program's disclosed reports."""
        log("info", f"Learning from {program} Hacktivity")

        reports = self.fetch_hacktivity(program=program, count=count)
        if not reports:
            log("warn", "No reports fetched")
            return {}

        # Cache reports
        cache_file = os.path.join(REPORTS_CACHE, f"{program}_reports.json")
        with open(cache_file, "w") as f:
            json.dump(reports, f, indent=2)

        knowledge = self.learn_from_reports(reports)

        # Generate program-specific skill file
        prog_skill = os.path.join(LEARNED_DIR, f"program_{program}.md")
        lines = [
            f"# Learned Patterns: {program}",
            f"\nBased on {len(reports)} disclosed reports.\n",
        ]

        for r in reports[:20]:
            severity = r.get("severity", "?")
            bounty = f"${r['bounty']}" if r.get("bounty") else "N/A"
            lines.append(f"- [{severity}] {r['title']} (bounty: {bounty})")

        with open(prog_skill, "w") as f:
            f.write("\n".join(lines))
        log("ok", f"Program skill saved: {prog_skill}")

        return knowledge

    def get_techniques_for(self, vuln_class):
        """Get learned techniques for a specific vuln class."""
        knowledge_file = os.path.join(LEARNED_DIR, "hacktivity_knowledge.json")
        if not os.path.exists(knowledge_file):
            return []

        try:
            with open(knowledge_file) as f:
                knowledge = json.load(f)
            vc_data = knowledge.get("vuln_classes", {}).get(vuln_class, {})
            return vc_data.get("top_reports", [])
        except:
            return []

    def suggest_hunt_strategy(self, tech_stack=None):
        """Suggest hunt strategy based on learned patterns."""
        knowledge_file = os.path.join(LEARNED_DIR, "hacktivity_knowledge.json")
        if not os.path.exists(knowledge_file):
            log("warn", "No learned knowledge yet. Run --learn-all first.")
            return {}

        with open(knowledge_file) as f:
            knowledge = json.load(f)

        sorted_by_roi = sorted(
            knowledge["vuln_classes"].items(),
            key=lambda x: x[1]["avg_bounty"] * x[1]["count"],
            reverse=True
        )

        strategy = {
            "priority_order": [vc for vc, _ in sorted_by_roi[:10]],
            "highest_bounty_class": sorted_by_roi[0][0] if sorted_by_roi else "unknown",
            "most_common_class": max(
                knowledge["vuln_classes"].items(),
                key=lambda x: x[1]["count"]
            )[0] if knowledge["vuln_classes"] else "unknown",
        }

        log("ok", "Hunt strategy:")
        for i, (vc, data) in enumerate(sorted_by_roi[:5], 1):
            log("info", f"  {i}. {vc} (ROI score: {data['avg_bounty'] * data['count']:.0f})")

        return strategy


def main():
    p = argparse.ArgumentParser(description="Hacktivity Self-Learning Engine")
    p.add_argument("--program", help="Learn from specific program")
    p.add_argument("--count", type=int, default=25, help="Reports to fetch")
    p.add_argument("--learn-all", action="store_true", help="Learn from top Hacktivity")
    p.add_argument("--suggest", action="store_true", help="Suggest hunt strategy")
    p.add_argument("--vuln-class", help="Get techniques for vuln class")
    args = p.parse_args()

    learner = HacktivityLearner()

    if args.suggest:
        strategy = learner.suggest_hunt_strategy()
        print(json.dumps(strategy, indent=2))
    elif args.vuln_class:
        techniques = learner.get_techniques_for(args.vuln_class)
        for t in techniques:
            print(f"  - {t}")
    elif args.program:
        learner.learn_program(args.program, count=args.count)
    elif args.learn_all:
        reports = learner.fetch_hacktivity(count=args.count)
        learner.learn_from_reports(reports)
    else:
        reports = learner.fetch_hacktivity(count=args.count)
        for r in reports[:10]:
            sev = r.get("severity", "?")
            log("info", f"[{sev}] {r['title']} ({r['program']})")


if __name__ == "__main__":
    main()
