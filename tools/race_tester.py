#!/usr/bin/env python3
"""
race_tester.py — Async Race Condition Tester

Tests for race conditions using parallel HTTP requests (Turbo Intruder style).
Finds: limit-overrun, double-spend, TOCTOU, coupon reuse, vote manipulation.

Usage:
    python3 race_tester.py --url https://target.com/api/redeem --method POST \
        --data '{"code":"PROMO50"}' --auth "Bearer TOKEN" --threads 20
"""
import asyncio
import aiohttp
import json
import os
import time
import hashlib
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse

# ── Race Attack Patterns ───────────────────────────────────────────────────────

RACE_PATTERNS = {
    "limit_overrun": {
        "description": "Send N identical requests to bypass single-use limits",
        "indicators": ["redeem", "coupon", "promo", "code", "credit", "gift",
                       "voucher", "discount", "reward", "claim", "activate"],
        "severity": "HIGH",
        "bounty_range": "$2K-$30K",
    },
    "double_spend": {
        "description": "Transfer/withdraw money twice by racing the balance check",
        "indicators": ["transfer", "withdraw", "send", "payment", "checkout",
                       "purchase", "buy", "order", "pay", "charge", "refund"],
        "severity": "CRITICAL",
        "bounty_range": "$10K-$50K",
    },
    "toctou": {
        "description": "Modify state between permission check and action",
        "indicators": ["update", "edit", "modify", "change", "settings",
                       "profile", "role", "permission", "approve", "verify"],
        "severity": "HIGH",
        "bounty_range": "$3K-$20K",
    },
    "vote_manipulation": {
        "description": "Register multiple votes/likes/ratings simultaneously",
        "indicators": ["vote", "like", "rate", "review", "upvote", "downvote",
                       "star", "favorite", "follow", "subscribe"],
        "severity": "MEDIUM",
        "bounty_range": "$500-$5K",
    },
    "signup_abuse": {
        "description": "Create multiple accounts racing email uniqueness check",
        "indicators": ["register", "signup", "sign-up", "create-account",
                       "onboard", "invite", "join"],
        "severity": "MEDIUM",
        "bounty_range": "$1K-$5K",
    },
}


class RaceTester:
    """Async race condition tester with multiple attack strategies."""

    def __init__(self, threads: int = 20, timeout: int = 10):
        self.threads = threads
        self.timeout = timeout
        self.results = []
        self.findings = []

    def detect_race_type(self, url: str, method: str = "POST",
                         data: str = "") -> list[dict]:
        """Auto-detect which race patterns apply to this endpoint."""
        url_lower = url.lower()
        data_lower = (data or "").lower()
        combined = url_lower + " " + data_lower

        matches = []
        for pattern_name, pattern in RACE_PATTERNS.items():
            for indicator in pattern["indicators"]:
                if indicator in combined:
                    matches.append({
                        "type": pattern_name,
                        "indicator": indicator,
                        **pattern,
                    })
                    break
        return matches

    async def _send_request(self, session: aiohttp.ClientSession,
                            url: str, method: str, headers: dict,
                            data: str, request_id: int) -> dict:
        """Send a single request and capture response."""
        t0 = time.monotonic()
        try:
            kwargs = {"headers": headers, "timeout": aiohttp.ClientTimeout(total=self.timeout)}
            if data:
                try:
                    json_data = json.loads(data)
                    kwargs["json"] = json_data
                except json.JSONDecodeError:
                    kwargs["data"] = data

            async with session.request(method, url, **kwargs) as resp:
                body = await resp.text()
                elapsed = round((time.monotonic() - t0) * 1000, 1)
                return {
                    "id": request_id,
                    "status": resp.status,
                    "body_length": len(body),
                    "body_hash": hashlib.md5(body.encode()).hexdigest()[:12],
                    "body_preview": body[:500],
                    "elapsed_ms": elapsed,
                    "headers": dict(resp.headers),
                }
        except Exception as e:
            return {
                "id": request_id,
                "status": 0,
                "error": str(e),
                "elapsed_ms": round((time.monotonic() - t0) * 1000, 1),
            }

    async def race_batch(self, url: str, method: str = "POST",
                         headers: dict = None, data: str = "",
                         count: int = None) -> dict:
        """Send N requests simultaneously — the core race attack."""
        count = count or self.threads
        headers = headers or {}

        # Use a single TCP connector for maximum concurrency
        connector = aiohttp.TCPConnector(limit=0, force_close=False)
        async with aiohttp.ClientSession(connector=connector) as session:
            # Pre-warm connections
            try:
                async with session.request("HEAD", url, headers=headers,
                                          timeout=aiohttp.ClientTimeout(total=5)):
                    pass
            except Exception:
                pass

            # Fire all requests simultaneously
            tasks = [
                self._send_request(session, url, method, headers, data, i)
                for i in range(count)
            ]
            results = await asyncio.gather(*tasks)

        return self._analyze_race_results(results, url, method)

    async def race_with_gate(self, url: str, gate_url: str,
                             method: str = "POST", gate_method: str = "GET",
                             headers: dict = None, data: str = "",
                             count: int = None) -> dict:
        """TOCTOU attack: race the action against a state-changing gate request.
        
        Example: Race PUT /api/settings (change email) against GET /api/verify-email
        """
        count = count or self.threads
        headers = headers or {}

        connector = aiohttp.TCPConnector(limit=0, force_close=False)
        async with aiohttp.ClientSession(connector=connector) as session:
            # Send gate request + action requests simultaneously
            gate_task = self._send_request(session, gate_url, gate_method,
                                          headers, "", 999)
            action_tasks = [
                self._send_request(session, url, method, headers, data, i)
                for i in range(count)
            ]
            all_tasks = [gate_task] + action_tasks
            results = await asyncio.gather(*all_tasks)

        gate_result = results[0]
        action_results = results[1:]
        analysis = self._analyze_race_results(action_results, url, method)
        analysis["gate_result"] = gate_result
        analysis["attack_type"] = "toctou"
        return analysis

    async def race_sequential_vs_parallel(self, url: str, method: str = "POST",
                                          headers: dict = None,
                                          data: str = "") -> dict:
        """Compare sequential vs parallel to prove race condition exists.
        
        If sequential gives different results than parallel, race condition confirmed.
        """
        headers = headers or {}

        # Sequential: send 3 requests one at a time
        connector = aiohttp.TCPConnector(limit=1)
        async with aiohttp.ClientSession(connector=connector) as session:
            sequential_results = []
            for i in range(3):
                result = await self._send_request(session, url, method,
                                                  headers, data, i)
                sequential_results.append(result)

        # Parallel: send 20 requests simultaneously
        parallel_result = await self.race_batch(url, method, headers, data, 20)

        # Compare: if parallel has more successes than sequential, race exists
        seq_successes = sum(1 for r in sequential_results
                          if r.get("status") in (200, 201, 204))
        par_successes = parallel_result.get("success_count", 0)

        confirmed = par_successes > seq_successes
        return {
            "race_confirmed": confirmed,
            "sequential_successes": seq_successes,
            "parallel_successes": par_successes,
            "confidence": "HIGH" if par_successes > seq_successes + 1 else
                         "MEDIUM" if par_successes > seq_successes else "LOW",
            "parallel_details": parallel_result,
            "sequential_details": sequential_results,
        }

    def _analyze_race_results(self, results: list[dict],
                              url: str, method: str) -> dict:
        """Analyze race results for signs of successful exploitation."""
        statuses = {}
        body_hashes = {}
        successes = 0
        errors = 0
        timings = []

        for r in results:
            status = r.get("status", 0)
            statuses[status] = statuses.get(status, 0) + 1
            if status in (200, 201, 204):
                successes += 1
            elif status == 0:
                errors += 1

            bhash = r.get("body_hash", "")
            if bhash:
                body_hashes[bhash] = body_hashes.get(bhash, 0) + 1

            if r.get("elapsed_ms"):
                timings.append(r["elapsed_ms"])

        # Detect race indicators
        indicators = []
        vuln_confirmed = False

        # Multiple 200s on single-use endpoint = limit-overrun
        if successes > 1:
            indicators.append(f"Multiple successes ({successes}/{len(results)}) — possible limit-overrun")
            if successes > 2:
                vuln_confirmed = True

        # Different response bodies = state inconsistency
        if len(body_hashes) > 1:
            indicators.append(f"Response body divergence ({len(body_hashes)} unique responses)")
            vuln_confirmed = True

        # Very tight timing cluster = requests arrived simultaneously
        if timings:
            timing_spread = max(timings) - min(timings)
            if timing_spread < 50:  # All within 50ms
                indicators.append(f"Tight timing cluster ({timing_spread:.0f}ms spread)")

        return {
            "url": url,
            "method": method,
            "total_requests": len(results),
            "success_count": successes,
            "error_count": errors,
            "status_distribution": statuses,
            "unique_responses": len(body_hashes),
            "timing_spread_ms": round(max(timings) - min(timings), 1) if timings else 0,
            "race_indicators": indicators,
            "vuln_confirmed": vuln_confirmed,
            "severity": "CRITICAL" if vuln_confirmed and successes > 2 else
                       "HIGH" if vuln_confirmed else "LOW",
            "raw_results": results[:5],  # First 5 for PoC
        }

    def save_findings(self, target: str) -> None:
        """Save race condition findings to disk."""
        out_dir = Path(f"findings/{target}/race")
        out_dir.mkdir(parents=True, exist_ok=True)
        if self.findings:
            out_file = out_dir / f"race_results_{int(time.time())}.json"
            out_file.write_text(json.dumps(self.findings, indent=2, default=str))

    def run(self, url: str, method: str = "POST", headers: dict = None,
            data: str = "", count: int = None, attack_type: str = "batch") -> dict:
        """Synchronous wrapper for the async race tester."""
        if attack_type == "compare":
            result = asyncio.run(
                self.race_sequential_vs_parallel(url, method, headers, data))
        else:
            result = asyncio.run(
                self.race_batch(url, method, headers, data, count))

        if result.get("vuln_confirmed") or result.get("race_confirmed"):
            self.findings.append(result)
        return result


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Race Condition Tester")
    parser.add_argument("--url", required=True, help="Target URL")
    parser.add_argument("--method", default="POST", help="HTTP method")
    parser.add_argument("--data", default="", help="POST body (JSON)")
    parser.add_argument("--auth", default="", help="Authorization header value")
    parser.add_argument("--cookie", default="", help="Cookie header")
    parser.add_argument("--threads", type=int, default=20, help="Concurrent requests")
    parser.add_argument("--compare", action="store_true",
                       help="Compare sequential vs parallel (proves race exists)")
    parser.add_argument("--target", default="", help="Target name for saving results")
    args = parser.parse_args()

    headers = {}
    if args.auth:
        headers["Authorization"] = args.auth
    if args.cookie:
        headers["Cookie"] = args.cookie

    tester = RaceTester(threads=args.threads)

    # Auto-detect race type
    matches = tester.detect_race_type(args.url, args.method, args.data)
    if matches:
        print(f"[+] Detected race patterns: {', '.join(m['type'] for m in matches)}")
        for m in matches:
            print(f"    {m['type']}: {m['description']} ({m['bounty_range']})")

    attack = "compare" if args.compare else "batch"
    result = tester.run(args.url, args.method, headers, args.data,
                       args.threads, attack)

    if result.get("vuln_confirmed") or result.get("race_confirmed"):
        print(f"\n[!!!] RACE CONDITION CONFIRMED")
        print(f"  Successes: {result.get('success_count', result.get('parallel_successes'))}")
        print(f"  Severity: {result.get('severity', result.get('confidence'))}")
    else:
        print(f"\n[-] No race condition detected")
        print(f"  Successes: {result.get('success_count', 0)}")

    if args.target:
        tester.save_findings(args.target)
