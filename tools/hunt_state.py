#!/usr/bin/env python3
"""
hunt_state.py — Crash-proof Hunt State Manager

Persists ALL hunt state to disk after every step. Survives:
- Auto-compact (Claude Code conversation truncation)
- Terminal crashes
- Session restarts

Every tool call, finding, phase transition, and decision is saved.
On resume, the hunt continues from the last saved state.

Usage:
    from hunt_state import HuntState
    state = HuntState("target.com")
    state.set_phase("recon")
    state.add_finding({...})
    state.save()  # called automatically after every mutation
"""
import json
import os
import time
from datetime import datetime
from pathlib import Path
from typing import Any


class HuntState:
    """Crash-proof hunt state manager with disk persistence."""

    def __init__(self, domain: str, base_dir: str = ""):
        self.domain = domain
        self.base_dir = Path(base_dir) if base_dir else Path("hunt-memory/sessions")
        self.base_dir.mkdir(parents=True, exist_ok=True)
        self.state_file = self.base_dir / f"{domain}_state.json"
        self.state = self._load_or_create()

    # New fields added in v2 — must be present in all state dicts
    _V2_DEFAULTS: dict = {
        "observations": [],
        "dead_ends": [],
        "hypotheses": [],
        "current_endpoint": "",
        "tested_classes": [],
    }

    def _load_or_create(self) -> dict:
        """Load existing state or create fresh. Migrates v1 state files in-place."""
        if self.state_file.exists():
            try:
                state = json.loads(self.state_file.read_text())
                # Migrate: add any missing v2 fields without touching existing data
                migrated = False
                for key, default in self._V2_DEFAULTS.items():
                    if key not in state:
                        state[key] = default
                        migrated = True
                if migrated:
                    self.state_file.write_text(json.dumps(state, indent=2, default=str))
                return state
            except Exception:
                pass

        return {
            "domain": self.domain,
            "created": datetime.now().isoformat(),
            "last_updated": datetime.now().isoformat(),
            "phase": "init",
            "step": 0,
            "total_steps": 0,

            # Scope
            "scope": {
                "in_scope": [],
                "out_scope": [],
                "program": "",
                "platform": "",
            },

            # Recon results
            "recon": {
                "subdomains": [],
                "live_hosts": [],
                "tech_stack": [],
                "urls_with_params": [],
                "endpoints_discovered": 0,
            },

            # Tool execution tracking
            "tools_completed": [],
            "tools_skipped": [],
            "tools_failed": [],
            "current_tool": "",

            # Findings
            "findings": [],
            "chains": [],
            "pocs_generated": [],

            # Endpoints tested
            "endpoints_tested": [],
            "endpoints_remaining": [],

            # Reports
            "reports_generated": [],

            # Token/model tracking
            "model_usage": {
                "total_steps": 0,
                "haiku_steps": 0,
                "sonnet_steps": 0,
                "opus_steps": 0,
            },

            # Hunt intelligence feed-back
            "hunt_intel": {
                "effective_tools": [],
                "wasted_tools": [],
                "tech_correlations": {},
            },

            # v2 persistence fields
            **self._V2_DEFAULTS,
        }

    def save(self) -> None:
        """Save state to disk (call after every mutation)."""
        self.state["last_updated"] = datetime.now().isoformat()
        self.state_file.write_text(
            json.dumps(self.state, indent=2, default=str))

    # ── Phase management ─────────────────────────────────────────────────

    def set_phase(self, phase: str) -> None:
        self.state["phase"] = phase
        self.save()

    def get_phase(self) -> str:
        return self.state["phase"]

    def increment_step(self) -> int:
        self.state["step"] += 1
        self.state["total_steps"] += 1
        self.save()
        return self.state["step"]

    # ── Tool tracking ────────────────────────────────────────────────────

    def start_tool(self, tool_name: str) -> None:
        self.state["current_tool"] = tool_name
        self.save()

    def complete_tool(self, tool_name: str, had_findings: bool = False,
                      duration: float = 0) -> None:
        self.state["tools_completed"].append({
            "name": tool_name,
            "timestamp": datetime.now().isoformat(),
            "had_findings": had_findings,
            "duration": round(duration, 1),
        })
        self.state["current_tool"] = ""

        if had_findings:
            self.state["hunt_intel"]["effective_tools"].append(tool_name)
        elif duration > 30:
            self.state["hunt_intel"]["wasted_tools"].append(tool_name)

        self.save()

    def skip_tool(self, tool_name: str, reason: str = "") -> None:
        self.state["tools_skipped"].append({
            "name": tool_name, "reason": reason,
            "timestamp": datetime.now().isoformat()})
        self.save()

    def fail_tool(self, tool_name: str, error: str = "") -> None:
        self.state["tools_failed"].append({
            "name": tool_name, "error": error[:200],
            "timestamp": datetime.now().isoformat()})
        self.save()

    def is_tool_completed(self, tool_name: str) -> bool:
        return any(t["name"] == tool_name
                   for t in self.state["tools_completed"])

    # ── Findings ─────────────────────────────────────────────────────────

    def add_finding(self, finding: dict) -> None:
        finding["timestamp"] = datetime.now().isoformat()
        self.state["findings"].append(finding)
        self.save()

    def add_chain(self, chain: dict) -> None:
        self.state["chains"].append(chain)
        self.save()

    # ── Scope ────────────────────────────────────────────────────────────

    def set_scope(self, in_scope: list, out_scope: list,
                  program: str = "", platform: str = "") -> None:
        self.state["scope"] = {
            "in_scope": in_scope,
            "out_scope": out_scope,
            "program": program,
            "platform": platform,
        }
        self.save()

    # ── Recon ────────────────────────────────────────────────────────────

    def set_recon(self, subdomains: list = None, live_hosts: list = None,
                  tech_stack: list = None, urls: list = None) -> None:
        if subdomains is not None:
            self.state["recon"]["subdomains"] = subdomains
        if live_hosts is not None:
            self.state["recon"]["live_hosts"] = live_hosts
        if tech_stack is not None:
            self.state["recon"]["tech_stack"] = tech_stack
        if urls is not None:
            self.state["recon"]["urls_with_params"] = urls
        self.save()

    # ── Model usage ──────────────────────────────────────────────────────

    def track_model(self, model: str) -> None:
        self.state["model_usage"]["total_steps"] += 1
        key = f"{model.lower()}_steps"
        if key in self.state["model_usage"]:
            self.state["model_usage"][key] += 1
        self.save()

    # ── Observations (auto-logged by PostToolUse hook, also callable manually) ──

    def add_observation(self, cmd: str, result: str, endpoint: str = "") -> None:
        """Append a tool observation. Keeps only the last 50 entries."""
        obs = {
            "ts": datetime.now().isoformat(),
            "cmd": cmd[:150],
            "result": result[:200],
            "endpoint": endpoint or self.state.get("current_endpoint", ""),
        }
        self.state["observations"].append(obs)
        # Rotate — keep last 50
        if len(self.state["observations"]) > 50:
            self.state["observations"] = self.state["observations"][-50:]
        self.save()

    # ── Dead ends ────────────────────────────────────────────────────────

    def add_dead_end(self, description: str) -> None:
        """Record something tried and confirmed FAILED. Prevents post-compact repeats."""
        self.state["dead_ends"].append(description)
        self.save()

    # ── Hypotheses ───────────────────────────────────────────────────────

    def add_hypothesis(self, hypothesis: str) -> None:
        """Add a new attack hypothesis to investigate."""
        self.state["hypotheses"].append(hypothesis)
        self.save()

    def remove_hypothesis(self, index: int) -> None:
        """Remove a hypothesis by index (0-based). Silently ignores out-of-range."""
        try:
            self.state["hypotheses"].pop(index)
            self.save()
        except IndexError:
            pass

    # ── Current endpoint ─────────────────────────────────────────────────

    def set_endpoint(self, endpoint: str) -> None:
        """Set the endpoint currently being tested."""
        self.state["current_endpoint"] = endpoint
        self.save()

    # ── Vuln class tracking ──────────────────────────────────────────────

    def mark_class_tested(self, vuln_class: str) -> None:
        """Mark one of the 24 vuln classes as tested."""
        if vuln_class not in self.state["tested_classes"]:
            self.state["tested_classes"].append(vuln_class)
            self.save()

    # ── Resume helpers ───────────────────────────────────────────────────

    def get_resumption_prompt(self) -> str:
        """Generate a prompt for Claude Code to resume from."""
        s = self.state
        completed = [t["name"] for t in s["tools_completed"]]
        findings_count = len(s["findings"])
        chains_count = len(s["chains"])

        prompt = f"""## RESUMING HUNT: {s['domain']}
Phase: {s['phase']} | Step: {s['step']} | Findings: {findings_count} | Chains: {chains_count}

### Completed tools ({len(completed)}):
{', '.join(completed) if completed else 'None'}

### Findings so far:
"""
        for f in s["findings"][:10]:
            prompt += f"- [{f.get('severity', '?')}] {f.get('type', '?')}: {f.get('url', '')[:80]}\n"

        if s.get("endpoints_remaining"):
            prompt += f"\n### Endpoints remaining: {len(s['endpoints_remaining'])}\n"

        prompt += f"\n### Next: Continue from phase '{s['phase']}', skip completed tools.\n"
        prompt += "DO NOT re-run completed tools. Pick up from the next unfinished step.\n"

        return prompt

    def get_recovery_summary(self) -> str:
        """Human-readable recovery summary for post-compact context injection."""
        s = self.state
        lines = [
            f"Target: {s['domain']} | Phase: {s['phase']} | Endpoint: {s.get('current_endpoint', 'none')}",
            f"Completed: {len(s['tools_completed'])} tools | Findings: {len(s['findings'])} | "
            f"Tested: {len(s.get('tested_classes', []))}/24 classes",
        ]

        observations = s.get("observations", [])[-5:]
        if observations:
            lines.append("Last 5 observations:")
            for o in observations:
                lines.append(f"  [{o['ts']}] {o['cmd']} => {o['result'][:100]}")

        hypotheses = s.get("hypotheses", [])
        if hypotheses:
            lines.append("Active hypotheses:")
            for h in hypotheses:
                lines.append(f"  - {h}")

        dead_ends = s.get("dead_ends", [])
        if dead_ends:
            lines.append("Dead ends (do not retry):")
            for d in dead_ends:
                lines.append(f"  - {d}")

        findings = s.get("findings", [])
        if findings:
            titles = [f.get("title", f.get("type", "untitled")) for f in findings]
            lines.append(f"Findings so far: {titles}")

        return "\n".join(lines)

    def get_status_summary(self) -> str:
        """One-line status for display."""
        s = self.state
        return (
            f"Phase: {s['phase']} | Step: {s['step']} | "
            f"Tools: {len(s['tools_completed'])} done, "
            f"{len(s['tools_failed'])} failed | "
            f"Findings: {len(s['findings'])} | "
            f"Chains: {len(s['chains'])}")
