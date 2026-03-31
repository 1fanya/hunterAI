#!/usr/bin/env python3
"""
Pattern Learner — Hunt Memory Intelligence System

Learns from successful hunts and saves patterns:
- Tech stack → vulnerability mapping
- Successful payload patterns
- Endpoint naming patterns that led to findings
- Company-specific patterns

When hunting a new target, queries memory for similar tech stacks
and suggests the most likely vulnerability classes to test first.

Usage:
    python3 pattern_learner.py --learn --target target.com --finding findings.json
    python3 pattern_learner.py --suggest --tech "nextjs,graphql,aws"
    python3 pattern_learner.py --stats
"""

import argparse
import json
import os
import sys
from datetime import datetime

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MEMORY_DIR = os.path.join(BASE_DIR, "hunt-memory")
PATTERNS_FILE = os.path.join(MEMORY_DIR, "patterns.json")

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


def load_patterns():
    """Load pattern database."""
    os.makedirs(MEMORY_DIR, exist_ok=True)
    if os.path.exists(PATTERNS_FILE):
        with open(PATTERNS_FILE) as f:
            return json.load(f)
    return {
        "tech_vuln_map": {},     # tech_stack_hash → [{vuln_class, count, avg_severity}]
        "payload_patterns": {},  # vuln_class → [payloads that worked]
        "endpoint_patterns": {}, # vuln_class → [endpoint patterns that had findings]
        "success_count": 0,
        "total_hunts": 0,
    }


def save_patterns(patterns):
    """Save pattern database."""
    os.makedirs(MEMORY_DIR, exist_ok=True)
    with open(PATTERNS_FILE, "w") as f:
        json.dump(patterns, f, indent=2)


def tech_hash(techs):
    """Create a sorted hash key from tech list."""
    return ",".join(sorted(t.lower().strip() for t in techs))


def learn_from_finding(patterns, target, techs, finding):
    """Learn from a successful finding."""
    vuln_class = finding.get("type", "unknown")
    severity = finding.get("severity", "MEDIUM")
    endpoint = finding.get("endpoint", "")
    payload = finding.get("payload", "")

    severity_scores = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
    score = severity_scores.get(severity, 2)

    # 1. Update tech → vulnerability mapping
    key = tech_hash(techs)
    if key not in patterns["tech_vuln_map"]:
        patterns["tech_vuln_map"][key] = {}

    if vuln_class not in patterns["tech_vuln_map"][key]:
        patterns["tech_vuln_map"][key][vuln_class] = {
            "count": 0, "total_severity": 0, "targets": [],
        }

    entry = patterns["tech_vuln_map"][key][vuln_class]
    entry["count"] += 1
    entry["total_severity"] += score
    if target not in entry["targets"]:
        entry["targets"].append(target)

    # 2. Save successful payload pattern
    if payload:
        if vuln_class not in patterns["payload_patterns"]:
            patterns["payload_patterns"][vuln_class] = []
        patterns["payload_patterns"][vuln_class].append({
            "payload": payload[:200],
            "target": target,
            "severity": severity,
            "date": datetime.now().isoformat(),
        })
        # Keep last 50 per vuln class
        patterns["payload_patterns"][vuln_class] = \
            patterns["payload_patterns"][vuln_class][-50:]

    # 3. Save endpoint pattern
    if endpoint:
        # Normalize endpoint pattern (replace UUIDs/IDs with {id})
        import re
        normalized = re.sub(r'/\d+', '/{id}', endpoint)
        normalized = re.sub(
            r'/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}',
            '/{uuid}', normalized,
        )

        if vuln_class not in patterns["endpoint_patterns"]:
            patterns["endpoint_patterns"][vuln_class] = []

        existing = [p["pattern"] for p in patterns["endpoint_patterns"][vuln_class]]
        if normalized not in existing:
            patterns["endpoint_patterns"][vuln_class].append({
                "pattern": normalized,
                "original": endpoint,
                "target": target,
                "date": datetime.now().isoformat(),
            })

    patterns["success_count"] += 1
    return patterns


def suggest_tests(patterns, techs):
    """Suggest vulnerability classes and payloads based on tech stack."""
    key = tech_hash(techs)
    suggestions = []

    # Exact match
    if key in patterns["tech_vuln_map"]:
        vulns = patterns["tech_vuln_map"][key]
        for vuln_class, data in sorted(
            vulns.items(), key=lambda x: x[1]["total_severity"], reverse=True
        ):
            suggestions.append({
                "vuln_class": vuln_class,
                "confidence": "HIGH",
                "seen_count": data["count"],
                "avg_severity": data["total_severity"] / data["count"],
                "targets_found_on": data["targets"][:3],
                "match_type": "exact_tech_match",
            })

    # Partial match (any tech in common)
    for stored_key, vulns in patterns["tech_vuln_map"].items():
        stored_techs = set(stored_key.split(","))
        query_techs = set(t.lower().strip() for t in techs)
        overlap = stored_techs & query_techs

        if overlap and stored_key != key:
            for vuln_class, data in vulns.items():
                # Check if already suggested
                if any(s["vuln_class"] == vuln_class for s in suggestions):
                    continue
                suggestions.append({
                    "vuln_class": vuln_class,
                    "confidence": "MEDIUM",
                    "seen_count": data["count"],
                    "avg_severity": data["total_severity"] / data["count"],
                    "targets_found_on": data["targets"][:3],
                    "match_type": f"partial_match ({', '.join(overlap)})",
                })

    # Add payload suggestions
    for s in suggestions:
        vuln = s["vuln_class"]
        if vuln in patterns.get("payload_patterns", {}):
            s["known_payloads"] = [
                p["payload"] for p in patterns["payload_patterns"][vuln][-3:]
            ]
        if vuln in patterns.get("endpoint_patterns", {}):
            s["known_endpoint_patterns"] = [
                p["pattern"] for p in patterns["endpoint_patterns"][vuln][-5:]
            ]

    return sorted(suggestions, key=lambda x: x.get("avg_severity", 0), reverse=True)


def print_suggestions(suggestions):
    """Print test suggestions."""
    print(f"\n{BOLD}{'='*60}{NC}")
    print(f"{BOLD}  Hunt Suggestions (from pattern memory){NC}")
    print(f"{'='*60}\n")

    if not suggestions:
        print(f"  {YELLOW}No patterns found for this tech stack.{NC}")
        print(f"  Run default test matrix.")
        return

    for i, s in enumerate(suggestions, 1):
        color = GREEN if s["confidence"] == "HIGH" else YELLOW
        print(f"  {color}{BOLD}#{i} {s['vuln_class']}{NC} "
              f"(confidence: {s['confidence']}, seen: {s['seen_count']}x)")
        print(f"    Match: {s['match_type']}")
        print(f"    Avg severity: {s['avg_severity']:.1f}/4")
        if s.get("targets_found_on"):
            print(f"    Found on: {', '.join(s['targets_found_on'])}")
        if s.get("known_payloads"):
            print(f"    Payloads: {', '.join(s['known_payloads'][:2])}")
        if s.get("known_endpoint_patterns"):
            print(f"    Endpoints: {', '.join(s['known_endpoint_patterns'][:3])}")
        print()


def print_stats(patterns):
    """Print pattern database stats."""
    print(f"\n{BOLD}{'='*60}{NC}")
    print(f"{BOLD}  Pattern Database Stats{NC}")
    print(f"{'='*60}\n")
    print(f"  Successful findings: {patterns['success_count']}")
    print(f"  Total hunts: {patterns['total_hunts']}")
    print(f"  Tech stacks: {len(patterns['tech_vuln_map'])}")
    print(f"  Vuln classes: {len(patterns.get('payload_patterns', {}))}")
    print(f"  Endpoint patterns: {sum(len(v) for v in patterns.get('endpoint_patterns', {}).values())}")

    if patterns["tech_vuln_map"]:
        print(f"\n  {CYAN}Top tech → vuln mappings:{NC}")
        for tech_key, vulns in list(patterns["tech_vuln_map"].items())[:5]:
            print(f"    {tech_key}:")
            for vuln, data in sorted(vulns.items(), key=lambda x: x[1]["count"], reverse=True):
                print(f"      → {vuln}: {data['count']}x")

    print()


def main():
    parser = argparse.ArgumentParser(description="Pattern Learner")
    parser.add_argument("--learn", action="store_true", help="Learn from a finding")
    parser.add_argument("--suggest", action="store_true", help="Get suggestions")
    parser.add_argument("--stats", action="store_true", help="Show stats")
    parser.add_argument("--target", help="Target domain")
    parser.add_argument("--tech", help="Comma-separated tech stack")
    parser.add_argument("--finding", help="Path to finding JSON")
    args = parser.parse_args()

    patterns = load_patterns()

    if args.learn:
        if not args.target:
            log("err", "--target required for --learn")
            sys.exit(1)

        techs = args.tech.split(",") if args.tech else []

        if args.finding and os.path.isfile(args.finding):
            with open(args.finding) as f:
                data = json.load(f)
            findings = data if isinstance(data, list) else data.get("findings", [data])
        else:
            log("err", "Provide --finding with path to findings JSON")
            sys.exit(1)

        for finding in findings:
            patterns = learn_from_finding(patterns, args.target, techs, finding)
            log("ok", f"Learned: {finding.get('type')} on {args.target}")

        patterns["total_hunts"] += 1
        save_patterns(patterns)

    elif args.suggest:
        if not args.tech:
            log("err", "--tech required for --suggest")
            sys.exit(1)
        techs = args.tech.split(",")
        suggestions = suggest_tests(patterns, techs)
        print_suggestions(suggestions)

    elif args.stats:
        print_stats(patterns)

    else:
        print_stats(patterns)


if __name__ == "__main__":
    main()
