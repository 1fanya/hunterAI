#!/usr/bin/env python3
"""
report_finalizer.py — Generates a professional H1-quality bug bounty report
from all findings discovered during a hunt.

Combines findings from all tools, deduplicates, sorts by severity,
generates PoCs, and outputs a single submission-ready report.

Usage:
    from report_finalizer import ReportFinalizer
    report = ReportFinalizer(domain="target.com")
    output = report.generate()
"""
import json
import os
import re
import time
from datetime import datetime
from pathlib import Path
from typing import Optional


class ReportFinalizer:
    """Generate professional H1-quality combined report from all findings."""

    SEVERITY_ORDER = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}

    def __init__(self, domain: str, findings_dir: str = ""):
        self.domain = domain
        self.findings_dir = Path(findings_dir) if findings_dir else Path(f"findings/{domain}")
        self.findings = []
        self.report_text = ""

    def collect_findings(self) -> list[dict]:
        """Collect all findings from the findings directory tree."""
        findings = []

        if not self.findings_dir.exists():
            return findings

        for json_file in self.findings_dir.rglob("*.json"):
            try:
                data = json.loads(json_file.read_text())
                if isinstance(data, list):
                    for item in data:
                        item.setdefault("source_file", str(json_file))
                        findings.append(item)
                elif isinstance(data, dict):
                    data.setdefault("source_file", str(json_file))
                    findings.append(data)
            except Exception:
                continue

        # Sort by severity
        findings.sort(
            key=lambda f: self.SEVERITY_ORDER.get(
                f.get("severity", "LOW"), 0),
            reverse=True)

        self.findings = findings
        return findings

    def deduplicate(self, findings: list[dict] = None) -> list[dict]:
        """Remove duplicate findings based on URL + type."""
        findings = findings or self.findings
        seen = set()
        unique = []

        for f in findings:
            url = f.get("url", f.get("endpoint", ""))
            # Normalize URL
            url_norm = re.sub(r'/\d+', '/{id}', url)
            vuln_type = f.get("type", f.get("vuln_type",
                             f.get("description", "")[:50]))

            key = (url_norm, vuln_type)
            if key not in seen:
                seen.add(key)
                unique.append(f)

        self.findings = unique
        return unique

    def severity_summary(self) -> dict:
        """Count findings by severity."""
        counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        for f in self.findings:
            sev = f.get("severity", "LOW").upper()
            counts[sev] = counts.get(sev, 0) + 1
        return counts

    def generate_executive_summary(self) -> str:
        """Generate executive summary section."""
        counts = self.severity_summary()
        total = sum(counts.values())

        text = f"# Security Assessment Report — {self.domain}\n\n"
        text += f"**Date:** {datetime.now().strftime('%Y-%m-%d')}\n"
        text += f"**Target:** {self.domain}\n"
        text += f"**Total Findings:** {total}\n\n"

        text += "## Executive Summary\n\n"

        if counts["CRITICAL"] > 0:
            text += (f"⚠️ **CRITICAL:** {counts['CRITICAL']} critical "
                    f"vulnerabilities require immediate remediation. "
                    f"These allow unauthorized access to sensitive data, "
                    f"remote code execution, or full infrastructure compromise.\n\n")
        elif counts["HIGH"] > 0:
            text += (f"**{counts['HIGH']} high-severity** vulnerabilities "
                    f"were discovered that should be prioritized for patching.\n\n")
        else:
            text += "No critical or high-severity vulnerabilities were found.\n\n"

        text += "### Severity Breakdown\n\n"
        text += "| Severity | Count |\n|----------|-------|\n"
        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
            if counts[sev] > 0:
                emoji = {"CRITICAL": "🔴", "HIGH": "🟠",
                         "MEDIUM": "🟡", "LOW": "🟢"}[sev]
                text += f"| {emoji} {sev} | {counts[sev]} |\n"
        text += "\n---\n\n"

        return text

    def format_finding(self, finding: dict, index: int) -> str:
        """Format a single finding as H1-style report section."""
        severity = finding.get("severity", "LOW")
        vuln_type = finding.get("type", finding.get("vuln_type",
                               finding.get("description", "Unknown")))
        url = finding.get("url", finding.get("endpoint", "N/A"))
        emoji = {"CRITICAL": "🔴", "HIGH": "🟠",
                 "MEDIUM": "🟡", "LOW": "🟢"}.get(severity, "⚪")

        text = f"## {emoji} Finding #{index}: {vuln_type}\n\n"
        text += f"**Severity:** {severity}\n"
        text += f"**URL:** `{url}`\n"

        if finding.get("param"):
            text += f"**Parameter:** `{finding['param']}`\n"
        if finding.get("method"):
            text += f"**Method:** {finding['method']}\n"

        text += "\n### Description\n\n"

        descriptions = {
            "idor": "Insecure Direct Object Reference allows accessing other users' resources by modifying resource identifiers.",
            "bola": "Broken Object Level Authorization — API fails to verify the requesting user owns the target resource.",
            "ssrf": "Server-Side Request Forgery allows making HTTP requests to internal services from the server.",
            "sqli": "SQL Injection enables extracting database contents through crafted input.",
            "xss": "Cross-Site Scripting allows injecting malicious JavaScript into pages viewed by other users.",
            "rce": "Remote Code Execution enables running arbitrary commands on the target server.",
            "race": "Race condition allows exploiting time-of-check to time-of-use gaps.",
            "cache": "Web Cache Poisoning allows serving attacker-controlled content to other users.",
            "proto": "Prototype Pollution enables injecting properties into JavaScript object prototypes.",
            "smuggle": "HTTP Request Smuggling allows desynchronizing front-end and back-end request parsing.",
            "graphql": "GraphQL security issue — potential data exposure, DoS, or authorization bypass.",
        }

        for key, desc in descriptions.items():
            if key in vuln_type.lower():
                text += f"{desc}\n\n"
                break
        else:
            text += f"{finding.get('description', 'Security vulnerability identified.')}\n\n"

        # Evidence
        if finding.get("evidence") or finding.get("hits") or finding.get("steps"):
            text += "### Evidence\n\n"
            evidence = (finding.get("evidence") or
                       finding.get("hits") or
                       finding.get("steps") or [])
            if isinstance(evidence, list):
                for ev in evidence[:5]:
                    if isinstance(ev, dict):
                        text += f"- {json.dumps(ev, indent=2, default=str)}\n"
                    else:
                        text += f"- {ev}\n"
            elif isinstance(evidence, str):
                text += f"```\n{evidence}\n```\n"
            text += "\n"

        # PoC curl command if available
        if finding.get("curl"):
            text += "### Proof of Concept\n\n"
            text += f"```bash\n{finding['curl']}\n```\n\n"

        text += "---\n\n"
        return text

    def generate(self, min_severity: str = "LOW") -> str:
        """Generate the full report."""
        self.collect_findings()
        self.deduplicate()

        # Filter by severity
        threshold = self.SEVERITY_ORDER.get(min_severity.upper(), 0)
        filtered = [
            f for f in self.findings
            if self.SEVERITY_ORDER.get(
                f.get("severity", "LOW").upper(), 0) >= threshold
        ]

        # Build report
        report = self.generate_executive_summary()

        if not filtered:
            report += "No findings at or above the severity threshold.\n"
        else:
            report += "## Detailed Findings\n\n"
            for i, finding in enumerate(filtered, 1):
                report += self.format_finding(finding, i)

        # Recommendations
        report += "## Recommendations\n\n"
        counts = self.severity_summary()
        if counts["CRITICAL"] > 0:
            report += "1. **Immediately** remediate all CRITICAL findings\n"
            report += "2. Conduct a follow-up assessment after fixes\n"
        if counts["HIGH"] > 0:
            report += "3. Prioritize HIGH severity findings within 1 week\n"
        report += "4. Implement a regular security testing cadence\n"
        report += "5. Review and harden all API authorization checks\n"

        self.report_text = report
        return report

    def save(self, filename: str = "") -> str:
        """Save report to file."""
        if not self.report_text:
            self.generate()

        out_dir = self.findings_dir / "reports"
        out_dir.mkdir(parents=True, exist_ok=True)

        fname = filename or f"report_{self.domain}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.md"
        out_path = out_dir / fname
        out_path.write_text(self.report_text)

        return str(out_path)

    def save_h1_submissions(self) -> list[str]:
        """Save individual H1-format submissions per finding."""
        paths = []
        out_dir = self.findings_dir / "reports" / "h1_submissions"
        out_dir.mkdir(parents=True, exist_ok=True)

        for i, finding in enumerate(self.findings, 1):
            severity = finding.get("severity", "LOW")
            if self.SEVERITY_ORDER.get(severity, 0) < 2:  # Skip LOW/INFO
                continue

            vuln_type = finding.get("type", finding.get("vuln_type", "vuln"))
            vuln_type = re.sub(r'[^a-zA-Z0-9]', '_', vuln_type)[:30]

            fname = f"h1_{i:02d}_{severity}_{vuln_type}.md"
            text = self.format_finding(finding, i)

            (out_dir / fname).write_text(text)
            paths.append(str(out_dir / fname))

        return paths
