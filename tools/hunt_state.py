#!/usr/bin/env python3
"""
Hunt State Manager — Session Persistence for Bug Bounty Hunting

Saves and restores complete hunt state so Claude Code can resume
exactly where it left off after closing and reopening.

State is saved to hunt-memory/sessions/<target>_state.json

Usage:
    from hunt_state import HuntStateManager
    
    state = HuntStateManager("target.com")
    state.load()  # Restore previous session
    
    # Update state during hunting
    state.set_phase("hunting")
    state.add_tested_endpoint("/api/v2/users/123")
    state.add_finding({"type": "idor", "endpoint": "/api/v2/users/{id}", ...})
    state.save()  # Persist to disk
    
    # Resume later
    state = HuntStateManager("target.com")
    state.load()
    print(state.get_untested_endpoints())
    print(state.get_phase())  # "hunting"
"""

import json
import os
import fcntl
from datetime import datetime
from copy import deepcopy

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SESSIONS_DIR = os.path.join(BASE_DIR, "hunt-memory", "sessions")


class HuntStateManager:
    """Manages persistent hunt state for session continuity."""

    def __init__(self, target, sessions_dir=None):
        self.target = target
        self.sessions_dir = sessions_dir or SESSIONS_DIR
        os.makedirs(self.sessions_dir, exist_ok=True)
        self.filepath = os.path.join(self.sessions_dir, f"{self._safe_name(target)}_state.json")
        self.state = self._empty_state()

    def _safe_name(self, target):
        """Convert target to safe filename."""
        return target.replace(".", "_").replace("/", "_").replace(":", "_").replace("*", "wildcard")

    def _empty_state(self):
        """Create empty state structure."""
        return {
            "version": "1.0",
            "target": self.target,
            "created_at": datetime.now().isoformat(),
            "updated_at": datetime.now().isoformat(),

            # Pipeline progress
            "phase": "not_started",  # not_started, scope, recon, ranking, hunting, validating, reporting, complete
            "phase_history": [],

            # Scope
            "scope": {
                "domains": [],
                "excluded_domains": [],
                "excluded_classes": [],
                "platform": "",
                "program_handle": "",
            },

            # Recon results summary
            "recon": {
                "completed": False,
                "subdomains_count": 0,
                "live_hosts_count": 0,
                "urls_count": 0,
                "nuclei_findings_count": 0,
                "tech_stack": {},
                "recon_dir": "",
            },

            # Attack surface ranking
            "ranking": {
                "completed": False,
                "p1_endpoints": [],
                "p2_endpoints": [],
                "kill_list": [],
            },

            # Hunting progress
            "hunting": {
                "current_endpoint_index": 0,
                "current_vuln_class": "",
                "tested_endpoints": [],
                "untested_endpoints": [],
                "partial_signals": [],
                "time_spent_minutes": 0,
            },

            # Findings
            "findings": [],
            "validated_findings": [],
            "killed_findings": [],
            "chain_candidates": [],

            # Reports
            "reports": {
                "generated": [],
                "submitted": [],
            },

            # Dedup
            "dedup": {
                "hacktivity_checked": False,
                "similar_reports": [],
            },

            # Model usage tracking
            "model_usage": {
                "haiku_calls": 0,
                "sonnet_calls": 0,
                "opus_calls": 0,
                "estimated_cost": 0.0,
            },

            # Session log (for resume context)
            "session_log": [],

            # Cost mode used
            "cost_mode": "balanced",
        }

    def load(self):
        """Load state from disk. Returns True if previous state found."""
        if not os.path.exists(self.filepath):
            return False

        try:
            with open(self.filepath, "r") as f:
                fcntl.flock(f, fcntl.LOCK_SH)
                saved = json.load(f)
                fcntl.flock(f, fcntl.LOCK_UN)

            # Merge saved state into current (preserves new fields from upgrades)
            self._merge_state(saved)
            return True

        except (json.JSONDecodeError, IOError, OSError) as e:
            print(f"[!] Warning: Could not load state from {self.filepath}: {e}")
            return False

    def save(self):
        """Save state to disk with file locking."""
        self.state["updated_at"] = datetime.now().isoformat()

        try:
            with open(self.filepath, "w") as f:
                fcntl.flock(f, fcntl.LOCK_EX)
                json.dump(self.state, f, indent=2, default=str)
                fcntl.flock(f, fcntl.LOCK_UN)
        except IOError as e:
            print(f"[-] Error saving state: {e}")

    def _merge_state(self, saved):
        """Merge saved state into current state, preserving new fields."""
        for key in saved:
            if key in self.state:
                if isinstance(self.state[key], dict) and isinstance(saved[key], dict):
                    self.state[key].update(saved[key])
                else:
                    self.state[key] = saved[key]

    # --- Phase management ---

    def get_phase(self):
        return self.state["phase"]

    def set_phase(self, phase):
        old_phase = self.state["phase"]
        self.state["phase"] = phase
        self.state["phase_history"].append({
            "from": old_phase,
            "to": phase,
            "at": datetime.now().isoformat(),
        })
        self.log(f"Phase: {old_phase} → {phase}")
        self.save()

    # --- Scope ---

    def set_scope(self, domains, excluded_domains=None, excluded_classes=None,
                  platform="", program_handle=""):
        self.state["scope"] = {
            "domains": domains,
            "excluded_domains": excluded_domains or [],
            "excluded_classes": excluded_classes or [],
            "platform": platform,
            "program_handle": program_handle,
        }
        self.save()

    def get_scope(self):
        return self.state["scope"]

    # --- Recon ---

    def set_recon_complete(self, subdomains=0, live_hosts=0, urls=0,
                           nuclei_findings=0, tech_stack=None, recon_dir=""):
        self.state["recon"] = {
            "completed": True,
            "subdomains_count": subdomains,
            "live_hosts_count": live_hosts,
            "urls_count": urls,
            "nuclei_findings_count": nuclei_findings,
            "tech_stack": tech_stack or {},
            "recon_dir": recon_dir,
        }
        self.save()

    # --- Ranking ---

    def set_ranking(self, p1_endpoints, p2_endpoints=None, kill_list=None):
        self.state["ranking"] = {
            "completed": True,
            "p1_endpoints": p1_endpoints,
            "p2_endpoints": p2_endpoints or [],
            "kill_list": kill_list or [],
        }
        # Initialize untested endpoints from ranking
        all_endpoints = p1_endpoints + (p2_endpoints or [])
        tested = set(self.state["hunting"]["tested_endpoints"])
        self.state["hunting"]["untested_endpoints"] = [
            ep for ep in all_endpoints if ep not in tested
        ]
        self.save()

    # --- Hunting ---

    def add_tested_endpoint(self, endpoint, vuln_class="", result="no_finding"):
        """Mark an endpoint as tested."""
        entry = {
            "endpoint": endpoint,
            "vuln_class": vuln_class,
            "result": result,
            "tested_at": datetime.now().isoformat(),
        }
        self.state["hunting"]["tested_endpoints"].append(endpoint)

        # Remove from untested
        untested = self.state["hunting"]["untested_endpoints"]
        if endpoint in untested:
            untested.remove(endpoint)

        self.log(f"Tested: {endpoint} [{vuln_class}] → {result}")
        self.save()

    def get_untested_endpoints(self):
        """Get list of endpoints not yet tested."""
        return self.state["hunting"]["untested_endpoints"]

    def get_tested_endpoints(self):
        """Get list of already-tested endpoints."""
        return self.state["hunting"]["tested_endpoints"]

    def add_partial_signal(self, endpoint, signal_type, details):
        """Record a partial signal for later investigation."""
        self.state["hunting"]["partial_signals"].append({
            "endpoint": endpoint,
            "signal_type": signal_type,
            "details": details,
            "found_at": datetime.now().isoformat(),
        })
        self.save()

    # --- Findings ---

    def add_finding(self, finding):
        """Add a confirmed finding."""
        finding["found_at"] = datetime.now().isoformat()
        finding["id"] = f"FIND-{len(self.state['findings']) + 1:03d}"
        self.state["findings"].append(finding)
        self.log(f"Finding: {finding['id']} — {finding.get('type', 'unknown')} on {finding.get('endpoint', 'unknown')}")
        self.save()
        return finding["id"]

    def validate_finding(self, finding_id, passed=True, notes=""):
        """Mark a finding as validated or killed."""
        for f in self.state["findings"]:
            if f.get("id") == finding_id:
                f["validated"] = passed
                f["validation_notes"] = notes
                f["validated_at"] = datetime.now().isoformat()

                if passed:
                    self.state["validated_findings"].append(finding_id)
                    self.log(f"Validated: {finding_id}")
                else:
                    self.state["killed_findings"].append(finding_id)
                    self.log(f"Killed: {finding_id} — {notes}")
                break
        self.save()

    def add_chain_candidate(self, finding_id, chain_type, potential_b):
        """Record a chain candidate (A→B potential)."""
        self.state["chain_candidates"].append({
            "finding_a": finding_id,
            "chain_type": chain_type,
            "potential_b": potential_b,
            "status": "untested",
            "added_at": datetime.now().isoformat(),
        })
        self.save()

    def get_findings(self, validated_only=False):
        if validated_only:
            return [f for f in self.state["findings"]
                    if f.get("id") in self.state["validated_findings"]]
        return self.state["findings"]

    # --- Reports ---

    def add_report(self, finding_id, report_path):
        self.state["reports"]["generated"].append({
            "finding_id": finding_id,
            "report_path": report_path,
            "generated_at": datetime.now().isoformat(),
        })
        self.save()

    # --- Model usage ---

    def track_model_call(self, model_name):
        key = f"{model_name}_calls"
        if key in self.state["model_usage"]:
            self.state["model_usage"][key] += 1

    # --- Session log ---

    def log(self, message):
        """Add entry to session log for resume context."""
        self.state["session_log"].append({
            "at": datetime.now().isoformat(),
            "msg": message,
        })
        # Keep last 200 log entries
        if len(self.state["session_log"]) > 200:
            self.state["session_log"] = self.state["session_log"][-200:]

    # --- Resume summary ---

    def get_resume_summary(self):
        """Generate a human-readable summary for resuming a hunt."""
        s = self.state
        lines = [
            f"╔══════════════════════════════════════════════════╗",
            f"║  HUNT STATE: {s['target']:<37}║",
            f"╚══════════════════════════════════════════════════╝",
            f"",
            f"  Phase:     {s['phase']}",
            f"  Started:   {s['created_at'][:19]}",
            f"  Updated:   {s['updated_at'][:19]}",
            f"  Cost mode: {s['cost_mode']}",
            f"",
        ]

        if s["recon"]["completed"]:
            r = s["recon"]
            lines.append(f"  Recon: ✓ {r['subdomains_count']} subs, "
                        f"{r['live_hosts_count']} live, {r['urls_count']} URLs, "
                        f"{r['nuclei_findings_count']} nuclei findings")

        if s["ranking"]["completed"]:
            rk = s["ranking"]
            lines.append(f"  Ranking: ✓ {len(rk['p1_endpoints'])} P1, "
                        f"{len(rk['p2_endpoints'])} P2, "
                        f"{len(rk['kill_list'])} killed")

        tested = len(s["hunting"]["tested_endpoints"])
        untested = len(s["hunting"]["untested_endpoints"])
        lines.append(f"  Endpoints: {tested} tested, {untested} remaining")

        lines.append(f"  Findings: {len(s['findings'])} total, "
                    f"{len(s['validated_findings'])} validated, "
                    f"{len(s['killed_findings'])} killed")

        if s["hunting"]["partial_signals"]:
            lines.append(f"  Partial signals: {len(s['hunting']['partial_signals'])}")

        if s["chain_candidates"]:
            untested_chains = [c for c in s["chain_candidates"] if c["status"] == "untested"]
            lines.append(f"  Chain candidates: {len(untested_chains)} untested")

        reports = len(s["reports"]["generated"])
        lines.append(f"  Reports: {reports} generated")

        mu = s["model_usage"]
        lines.append(f"\n  Model calls: Haiku={mu['haiku_calls']}, "
                    f"Sonnet={mu['sonnet_calls']}, Opus={mu['opus_calls']}")

        # Recent session log
        recent = s["session_log"][-10:]
        if recent:
            lines.append(f"\n  Recent activity:")
            for entry in recent:
                lines.append(f"    [{entry['at'][11:19]}] {entry['msg']}")

        # Next action
        lines.append(f"\n  ► Next: ", )
        if s["phase"] == "not_started":
            lines[-1] += "Start with scope import"
        elif s["phase"] == "scope":
            lines[-1] += "Run recon"
        elif s["phase"] == "recon":
            lines[-1] += "Rank attack surface"
        elif s["phase"] == "ranking":
            lines[-1] += "Begin hunting"
        elif s["phase"] == "hunting":
            if untested > 0:
                next_ep = s["hunting"]["untested_endpoints"][0]
                lines[-1] += f"Continue hunting — next: {next_ep}"
            else:
                lines[-1] += "All endpoints tested — validate findings"
        elif s["phase"] == "validating":
            lines[-1] += "Continue validation / generate reports"
        elif s["phase"] == "reporting":
            lines[-1] += "Review and submit reports"
        elif s["phase"] == "complete":
            lines[-1] += "Hunt complete — review reports"

        return "\n".join(lines)


def main():
    """CLI for managing hunt state."""
    import argparse

    parser = argparse.ArgumentParser(description="Hunt State Manager")
    parser.add_argument("target", help="Target domain")
    parser.add_argument("--show", action="store_true", help="Show current state")
    parser.add_argument("--reset", action="store_true", help="Reset state")
    parser.add_argument("--json", action="store_true", help="Output raw JSON")
    args = parser.parse_args()

    state = HuntStateManager(args.target)

    if args.reset:
        state.save()
        print(f"State reset for {args.target}")
        return

    found = state.load()

    if args.json:
        print(json.dumps(state.state, indent=2))
    elif found:
        print(state.get_resume_summary())
    else:
        print(f"No previous state found for {args.target}")
        print("Start a new hunt with: /fullhunt " + args.target)


if __name__ == "__main__":
    main()
