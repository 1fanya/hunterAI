#!/usr/bin/env python3
"""
hunt_intel.py — Cross-Hunt Intelligence Engine

Learns from ALL past hunts to evolve strategy:
1. Tracks which tools found vulns vs wasted time
2. Records which vuln types appeared per tech stack
3. Adjusts tool priority based on historical success
4. Saves target-specific knowledge for re-hunts

Usage:
    from hunt_intel import HuntIntel
    intel = HuntIntel()
    intel.record_hunt("target.com", findings, tool_stats)
    strategy = intel.suggest_strategy("new-target.com", tech_stack)
"""
import json
import os
import time
from collections import defaultdict
from datetime import datetime
from pathlib import Path


class HuntIntel:
    """Cross-hunt intelligence and strategy evolution."""

    def __init__(self, data_dir: str = ""):
        self.data_dir = Path(data_dir) if data_dir else Path("hunt-memory/intel")
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.hunts_file = self.data_dir / "hunt_history.json"
        self.tool_stats_file = self.data_dir / "tool_stats.json"
        self.pattern_file = self.data_dir / "vuln_patterns.json"

        self.hunts = self._load(self.hunts_file, [])
        self.tool_stats = self._load(self.tool_stats_file, {})
        self.patterns = self._load(self.pattern_file, {})

    def _load(self, path: Path, default):
        if path.exists():
            try:
                return json.loads(path.read_text())
            except Exception:
                pass
        return default

    def _save(self):
        self.hunts_file.write_text(json.dumps(self.hunts, indent=2, default=str))
        self.tool_stats_file.write_text(json.dumps(self.tool_stats, indent=2, default=str))
        self.pattern_file.write_text(json.dumps(self.patterns, indent=2, default=str))

    def record_hunt(self, domain: str, findings: list[dict],
                    tools_used: list[dict], tech_stack: list[str] = None):
        """Record results from a completed hunt."""
        hunt = {
            "domain": domain,
            "timestamp": datetime.now().isoformat(),
            "findings_count": len(findings),
            "tools_used": len(tools_used),
            "tech_stack": tech_stack or [],
            "finding_types": [],
            "successful_tools": [],
            "wasted_tools": [],
        }

        # Classify findings
        finding_types = defaultdict(int)
        for f in findings:
            vuln_type = f.get("type", f.get("vuln_type", "unknown"))
            severity = f.get("severity", "LOW")
            finding_types[vuln_type] += 1
            hunt["finding_types"].append({
                "type": vuln_type, "severity": severity})

        # Classify tools by effectiveness
        for tool in tools_used:
            name = tool.get("name", "")
            had_findings = tool.get("findings_count", 0) > 0
            duration = tool.get("duration", 0)

            if had_findings:
                hunt["successful_tools"].append(name)
            elif duration > 30:
                hunt["wasted_tools"].append(name)

            # Update global tool stats
            if name not in self.tool_stats:
                self.tool_stats[name] = {
                    "hunts_used": 0, "hunts_found": 0,
                    "total_findings": 0, "avg_time": 0,
                    "success_rate": 0.0,
                }

            stats = self.tool_stats[name]
            stats["hunts_used"] += 1
            if had_findings:
                stats["hunts_found"] += 1
                stats["total_findings"] += tool.get("findings_count", 0)
            stats["success_rate"] = (
                stats["hunts_found"] / stats["hunts_used"]
                if stats["hunts_used"] > 0 else 0)

        # Record tech stack → vulnerability correlations
        for tech in (tech_stack or []):
            tech_key = tech.lower()
            if tech_key not in self.patterns:
                self.patterns[tech_key] = {
                    "seen_count": 0,
                    "vuln_types": defaultdict(int),
                    "effective_tools": defaultdict(int),
                }
            self.patterns[tech_key]["seen_count"] += 1
            for vt, count in finding_types.items():
                self.patterns[tech_key]["vuln_types"][vt] = (
                    self.patterns[tech_key].get("vuln_types", {}).get(vt, 0) + count)
            for tool in hunt["successful_tools"]:
                self.patterns[tech_key]["effective_tools"][tool] = (
                    self.patterns[tech_key].get("effective_tools", {}).get(tool, 0) + 1)

        self.hunts.append(hunt)
        self._save()

    def suggest_strategy(self, domain: str = "",
                         tech_stack: list[str] = None) -> dict:
        """Suggest hunt strategy based on historical intelligence."""
        strategy = {
            "domain": domain,
            "recommended_tools": [],
            "skip_tools": [],
            "expected_vuln_types": [],
            "confidence": "LOW",
        }

        if not self.tool_stats:
            strategy["note"] = "No hunt history — using default priority"
            return strategy

        # Rank tools by success rate
        ranked = sorted(
            self.tool_stats.items(),
            key=lambda x: (x[1]["success_rate"], x[1]["total_findings"]),
            reverse=True)

        strategy["recommended_tools"] = [
            {"name": name, "success_rate": f"{s['success_rate']:.0%}",
             "total_findings": s["total_findings"]}
            for name, s in ranked[:10] if s["success_rate"] > 0]

        strategy["skip_tools"] = [
            name for name, s in ranked if
            s["hunts_used"] >= 3 and s["success_rate"] == 0]

        # Tech-stack specific recommendations
        for tech in (tech_stack or []):
            tech_key = tech.lower()
            pattern = self.patterns.get(tech_key, {})
            if pattern and pattern.get("seen_count", 0) > 0:
                vuln_types = pattern.get("vuln_types", {})
                if vuln_types:
                    ranked_vulns = sorted(vuln_types.items(),
                                         key=lambda x: x[1], reverse=True)
                    strategy["expected_vuln_types"].extend(
                        [v for v, c in ranked_vulns[:5]])

        if len(self.hunts) >= 5:
            strategy["confidence"] = "HIGH"
        elif len(self.hunts) >= 2:
            strategy["confidence"] = "MEDIUM"

        return strategy

    def get_target_history(self, domain: str) -> dict:
        """Get previous hunt data for a specific target."""
        prev_hunts = [h for h in self.hunts if h["domain"] == domain]

        if not prev_hunts:
            return {"domain": domain, "previous_hunts": 0}

        return {
            "domain": domain,
            "previous_hunts": len(prev_hunts),
            "last_hunt": prev_hunts[-1]["timestamp"],
            "total_findings": sum(h["findings_count"] for h in prev_hunts),
            "known_vuln_types": list(set(
                f["type"] for h in prev_hunts
                for f in h.get("finding_types", []))),
            "effective_tools": list(set(
                t for h in prev_hunts
                for t in h.get("successful_tools", []))),
        }

    def get_stats_summary(self) -> dict:
        """Get overall intelligence summary."""
        total_findings = sum(h["findings_count"] for h in self.hunts)
        return {
            "total_hunts": len(self.hunts),
            "total_findings": total_findings,
            "unique_targets": len(set(h["domain"] for h in self.hunts)),
            "top_tools": sorted(
                [(n, s["success_rate"]) for n, s in self.tool_stats.items()],
                key=lambda x: x[1], reverse=True)[:5],
            "tech_stacks_seen": len(self.patterns),
        }
