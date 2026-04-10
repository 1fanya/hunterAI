#!/usr/bin/env python3
"""
auth_pair.py — Manage two authenticated sessions for IDOR/BOLA testing.

Usage:
    from auth_pair import AuthPair

    pair = AuthPair.load("target_name")

    # Test IDOR: request as attacker using victim's resource ID
    r_legit  = pair.get_as_victim("/api/orders/123")    # should work
    r_attack = pair.get_as_attacker("/api/orders/123")  # should fail (403/404)

    if r_attack.status_code == 200:
        # IDOR confirmed — attacker can access victim's order
        diff = pair.diff_responses(r_legit, r_attack)
"""

import json
import time
from pathlib import Path
from typing import Optional, Dict, Any

try:
    import requests
except ImportError:
    requests = None


class AuthPair:
    """Two authenticated sessions for IDOR/BOLA testing."""

    def __init__(self, target: str, attacker: Dict[str, str], victim: Dict[str, str],
                 base_url: str = "", rate_limit: float = 0.5):
        self.target = target
        self.attacker = attacker  # {"cookies": {...}, "headers": {...}}
        self.victim = victim
        self.base_url = base_url.rstrip("/")
        self.rate_limit = rate_limit  # seconds between requests
        self._session_a = requests.Session() if requests else None
        self._session_v = requests.Session() if requests else None
        self._setup_sessions()

    def _setup_sessions(self):
        """Configure both sessions with auth."""
        for session, auth in [(self._session_a, self.attacker), (self._session_v, self.victim)]:
            if session is None:
                continue
            if "cookies" in auth:
                for k, v in auth["cookies"].items():
                    session.cookies.set(k, v)
            if "headers" in auth:
                session.headers.update(auth["headers"])
            session.headers.setdefault("User-Agent", "Mozilla/5.0 HunterAI-Research")

    @classmethod
    def load(cls, target: str) -> "AuthPair":
        """Load auth pair from hunt-memory/<target>/auth-pair.json"""
        path = Path(f"hunt-memory/{target}/auth-pair.json")
        if not path.exists():
            intel_path = Path(f"hunt-memory/{target}/app-intel.md")
            if intel_path.exists():
                raise FileNotFoundError(
                    f"auth-pair.json not found. Extract tokens from app-intel.md:\n"
                    f"python3 tools/auth_pair.py --init {target}"
                )
            raise FileNotFoundError(
                f"No auth pair for {target}. Create hunt-memory/{target}/auth-pair.json:\n"
                f'{{"base_url": "https://{target}", '
                f'"attacker": {{"cookies": {{"session": "..."}}}}, '
                f'"victim": {{"cookies": {{"session": "..."}}}}}}'
            )
        with open(path) as f:
            data = json.load(f)
        return cls(
            target=target,
            attacker=data["attacker"],
            victim=data["victim"],
            base_url=data.get("base_url", ""),
            rate_limit=data.get("rate_limit", 0.5),
        )

    def save(self, target: str):
        """Save auth pair to disk."""
        path = Path(f"hunt-memory/{target}/auth-pair.json")
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "w") as f:
            json.dump({
                "base_url": self.base_url,
                "attacker": self.attacker,
                "victim": self.victim,
                "rate_limit": self.rate_limit,
            }, f, indent=2)

    def _request(self, session: "requests.Session", method: str, path: str, **kwargs) -> "requests.Response":
        """Make a rate-limited request."""
        url = f"{self.base_url}{path}" if not path.startswith("http") else path
        time.sleep(self.rate_limit)
        return session.request(method, url, timeout=15, allow_redirects=False, **kwargs)

    def get_as_attacker(self, path: str, **kwargs) -> "requests.Response":
        return self._request(self._session_a, "GET", path, **kwargs)

    def get_as_victim(self, path: str, **kwargs) -> "requests.Response":
        return self._request(self._session_v, "GET", path, **kwargs)

    def post_as_attacker(self, path: str, **kwargs) -> "requests.Response":
        return self._request(self._session_a, "POST", path, **kwargs)

    def post_as_victim(self, path: str, **kwargs) -> "requests.Response":
        return self._request(self._session_v, "POST", path, **kwargs)

    def test_idor(self, path: str, method: str = "GET", **kwargs) -> Dict[str, Any]:
        """
        Test an endpoint for IDOR.
        Makes request as victim (should succeed) then as attacker (should fail).
        Returns analysis dict.
        """
        r_victim   = self._request(self._session_v, method, path, **kwargs)
        r_attacker = self._request(self._session_a, method, path, **kwargs)

        result: Dict[str, Any] = {
            "endpoint": path,
            "method": method,
            "victim_status": r_victim.status_code,
            "attacker_status": r_attacker.status_code,
            "idor_likely": False,
            "details": "",
        }

        if r_victim.status_code == 200 and r_attacker.status_code == 200:
            if r_victim.text == r_attacker.text:
                result["idor_likely"] = True
                result["details"] = "Identical responses — attacker sees victim's data"
            elif len(r_attacker.text) > 100:
                result["idor_likely"] = True
                result["details"] = f"Both 200, different bodies. Attacker response: {len(r_attacker.text)} bytes"

            # Check for PII fields in attacker response
            pii_indicators = ["email", "phone", "address", "ssn", "dob", "birth",
                               "password", "secret", "token"]
            body_lower = r_attacker.text.lower()
            found_pii = [p for p in pii_indicators if p in body_lower]
            if found_pii:
                result["idor_likely"] = True
                result["details"] += f" PII fields in attacker response: {found_pii}"

        return result

    def diff_responses(self, r1: "requests.Response", r2: "requests.Response") -> str:
        """Human-readable diff between two responses."""
        lines = [
            f"Status: {r1.status_code} vs {r2.status_code}",
            f"Length: {len(r1.text)} vs {len(r2.text)}",
        ]

        try:
            j1, j2 = r1.json(), r2.json()
            keys1 = set(self._flatten_keys(j1))
            keys2 = set(self._flatten_keys(j2))
            if keys1 != keys2:
                lines.append(f"Extra keys in r1: {keys1 - keys2}")
                lines.append(f"Extra keys in r2: {keys2 - keys1}")
            for key in keys1 & keys2:
                v1 = self._get_nested(j1, key)
                v2 = self._get_nested(j2, key)
                if v1 != v2:
                    lines.append(f"Different value for '{key}': {str(v1)[:50]} vs {str(v2)[:50]}")
        except (json.JSONDecodeError, AttributeError):
            if r1.text != r2.text:
                lines.append("Bodies differ (non-JSON)")

        return "\n".join(lines)

    def _flatten_keys(self, obj, prefix=""):
        """Flatten JSON keys for comparison."""
        keys = []
        if isinstance(obj, dict):
            for k, v in obj.items():
                full = f"{prefix}.{k}" if prefix else k
                keys.append(full)
                keys.extend(self._flatten_keys(v, full))
        elif isinstance(obj, list) and obj:
            keys.extend(self._flatten_keys(obj[0], f"{prefix}[0]"))
        return keys

    def _get_nested(self, obj, key) -> Optional[Any]:
        """Get nested value by dot-path."""
        parts = key.replace("[0]", ".0").split(".")
        current = obj
        for p in parts:
            try:
                current = current[int(p)] if p.isdigit() else current[p]
            except (KeyError, IndexError, TypeError):
                return None
        return current


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Auth pair manager for IDOR testing")
    parser.add_argument("--init", metavar="TARGET", help="Initialize auth-pair.json template")
    parser.add_argument("--test", metavar="TARGET", help="Quick IDOR test")
    parser.add_argument("--path", default="/api/v1/me", help="Endpoint to test (with --test)")
    args = parser.parse_args()

    if args.init:
        target = args.init
        out_path = Path(f"hunt-memory/{target}/auth-pair.json")
        out_path.parent.mkdir(parents=True, exist_ok=True)
        template = {
            "base_url": f"https://{target}",
            "attacker": {"cookies": {"session": "ATTACKER_SESSION_HERE"}, "headers": {}},
            "victim":   {"cookies": {"session": "VICTIM_SESSION_HERE"},   "headers": {}},
            "rate_limit": 0.5,
        }
        with open(out_path, "w") as f:
            json.dump(template, f, indent=2)
        print(f"Created {out_path} — fill in session tokens for both accounts.")

    elif args.test:
        pair = AuthPair.load(args.test)
        result = pair.test_idor(args.path)
        print(json.dumps(result, indent=2))
