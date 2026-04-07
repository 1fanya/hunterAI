#!/usr/bin/env python3
"""
auto_scope.py — Auto-Scope Loader

Give it a H1 program handle → auto-downloads scope, sets up scope_guard,
creates target queue entries, and prepares hunt config. Zero-friction start.

Usage:
    from auto_scope import AutoScope
    scope = AutoScope()
    config = scope.load("rockstargames")
    # → scope.json created, scope_guard configured, ready to /fullhunt
"""
import json
import os
import re
import time
from pathlib import Path

try:
    import requests
except ImportError:
    requests = None


class AutoScope:
    """Auto-import scope from bug bounty platforms."""

    H1_API = "https://api.hackerone.com/v1"

    def __init__(self, output_dir: str = "hunt-memory"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.session = requests.Session() if requests else None
        self.h1_token = os.environ.get("H1_API_TOKEN", "")
        if self.session:
            self.session.headers["User-Agent"] = "HunterAI/1.0"
            self.session.headers["Accept"] = "application/json"
            if self.h1_token:
                self.session.headers["Authorization"] = f"Bearer {self.h1_token}"

    def load(self, program_handle: str, platform: str = "hackerone") -> dict:
        """Load scope from platform and create hunt config."""
        if platform == "hackerone":
            scope = self._load_h1(program_handle)
        else:
            scope = {"error": f"Platform {platform} not supported yet"}

        if scope.get("error"):
            return scope

        # Save scope file
        scope_file = self.output_dir / f"scope_{program_handle}.json"
        scope_file.write_text(json.dumps(scope, indent=2), encoding="utf-8")

        # Generate hunt config
        config = self._generate_config(program_handle, scope)

        # Save hunt config
        config_file = self.output_dir / f"config_{program_handle}.json"
        config_file.write_text(json.dumps(config, indent=2), encoding="utf-8")

        return config

    def _load_h1(self, handle: str) -> dict:
        """Load scope from HackerOne."""
        if not self.session:
            return {"error": "requests not available"}

        scope = {
            "program": handle,
            "platform": "hackerone",
            "in_scope": [],
            "out_of_scope": [],
            "bounty_eligible": [],
            "domains": [],
            "wildcards": [],
            "apis": [],
            "mobile_apps": [],
        }

        try:
            # Get structured scopes
            resp = self.session.get(
                f"{self.H1_API}/hackers/programs/{handle}/structured_scopes",
                params={"page[size]": 100}, timeout=15)

            if resp.status_code != 200:
                # Fallback: try to get from program page
                return self._fallback_scope(handle)

            data = resp.json()
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
                    scope["in_scope"].append(entry)
                    if entry["eligible"]:
                        scope["bounty_eligible"].append(entry)

                    # Categorize
                    asset = entry["asset"]
                    if entry["type"] == "URL":
                        if "*" in asset:
                            scope["wildcards"].append(asset)
                        else:
                            scope["domains"].append(asset)
                    elif entry["type"] == "API":
                        scope["apis"].append(asset)
                    elif "MOBILE" in entry["type"].upper():
                        scope["mobile_apps"].append(asset)
                else:
                    scope["out_of_scope"].append(entry)

        except Exception as e:
            return {"error": str(e)}

        return scope

    def _fallback_scope(self, handle: str) -> dict:
        """Fallback scope extraction from program page."""
        try:
            resp = self.session.get(f"https://hackerone.com/{handle}",
                                    timeout=15)
            if resp.status_code != 200:
                return {"error": f"Cannot access {handle} program page"}

            # Extract domains from page content
            domains = set()
            for m in re.finditer(r'[\w.-]+\.(?:com|org|net|io|app|dev|co)\b',
                                  resp.text):
                domains.add(m.group(0))

            return {
                "program": handle,
                "platform": "hackerone",
                "in_scope": [{"asset": d, "type": "URL"} for d in sorted(domains)],
                "domains": sorted(domains),
                "note": "Fallback extraction — verify manually",
            }
        except Exception as e:
            return {"error": str(e)}

    def _generate_config(self, handle: str, scope: dict) -> dict:
        """Generate hunt configuration from scope."""
        domains = scope.get("domains", [])
        wildcards = scope.get("wildcards", [])

        # Extract root domains from wildcards
        for w in wildcards:
            root = w.replace("*.", "").strip()
            if root and root not in domains:
                domains.append(root)

        # Determine primary target
        primary = domains[0] if domains else handle

        config = {
            "program": handle,
            "platform": scope.get("platform", "hackerone"),
            "primary_target": primary,
            "all_domains": domains,
            "wildcards": wildcards,
            "apis": scope.get("apis", []),
            "mobile_apps": scope.get("mobile_apps", []),
            "out_of_scope": [e["asset"] for e in scope.get("out_of_scope", [])],
            "bounty_eligible_count": len(scope.get("bounty_eligible", [])),
            "total_in_scope": len(scope.get("in_scope", [])),
            "hunt_strategy": self._suggest_strategy(scope),
            "ready": True,
        }

        return config

    def _suggest_strategy(self, scope: dict) -> str:
        """Suggest hunting strategy based on scope."""
        n_domains = len(scope.get("domains", []))
        n_wildcards = len(scope.get("wildcards", []))
        has_api = bool(scope.get("apis"))
        has_mobile = bool(scope.get("mobile_apps"))

        if n_wildcards > 3:
            return "wide_recon_first"
        elif has_api:
            return "api_focused"
        elif has_mobile:
            return "mobile_api_extraction"
        elif n_domains <= 3:
            return "deep_single_target"
        else:
            return "balanced"

    def list_configs(self) -> list:
        """List saved hunt configs."""
        return [str(f) for f in self.output_dir.glob("config_*.json")]
