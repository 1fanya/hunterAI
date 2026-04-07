#!/usr/bin/env python3
"""
multi_target.py — Multi-Target Hunting Queue

Feed multiple programs, Claude hunts them in priority order.
Passive recon runs on all, active hunting on the most promising.

Usage:
    from multi_target import MultiTargetQueue
    queue = MultiTargetQueue()
    queue.add("uber.com", program="uber", platform="hackerone", priority=9)
    queue.add("twitter.com", program="twitter", platform="hackerone", priority=7)
    next_target = queue.next()
"""
import json
import time
from pathlib import Path


class MultiTargetQueue:
    """Priority-based multi-target hunting queue."""

    def __init__(self, queue_file: str = "hunt-memory/target_queue.json"):
        self.queue_file = Path(queue_file)
        self.queue_file.parent.mkdir(parents=True, exist_ok=True)
        self.targets = self._load()

    def _load(self) -> list:
        if self.queue_file.exists():
            try:
                return json.loads(self.queue_file.read_text(encoding="utf-8"))
            except Exception:
                pass
        return []

    def _save(self):
        self.queue_file.write_text(
            json.dumps(self.targets, indent=2, default=str),
            encoding="utf-8")

    def add(self, domain: str, program: str = "", platform: str = "hackerone",
            priority: int = 5, max_bounty: int = 0, tags: list = None) -> None:
        """Add target to queue."""
        # Check if already exists
        for t in self.targets:
            if t["domain"] == domain:
                t["priority"] = priority
                self._save()
                return

        self.targets.append({
            "domain": domain,
            "program": program,
            "platform": platform,
            "priority": priority,
            "max_bounty": max_bounty,
            "tags": tags or [],
            "status": "queued",
            "added": time.strftime("%Y-%m-%d %H:%M"),
            "recon_done": False,
            "hunt_done": False,
            "findings_count": 0,
            "last_hunted": None,
        })
        self.targets.sort(key=lambda x: x["priority"], reverse=True)
        self._save()

    def next(self) -> dict:
        """Get next target to hunt (highest priority, not completed)."""
        for t in self.targets:
            if t["status"] in ("queued", "recon_done"):
                return t
        return {}

    def next_recon(self) -> dict:
        """Get next target needing recon."""
        for t in self.targets:
            if not t["recon_done"]:
                return t
        return {}

    def complete_recon(self, domain: str) -> None:
        """Mark recon as completed for a target."""
        for t in self.targets:
            if t["domain"] == domain:
                t["recon_done"] = True
                t["status"] = "recon_done"
                break
        self._save()

    def complete_hunt(self, domain: str, findings: int = 0) -> None:
        """Mark hunt as completed."""
        for t in self.targets:
            if t["domain"] == domain:
                t["hunt_done"] = True
                t["status"] = "completed"
                t["findings_count"] = findings
                t["last_hunted"] = time.strftime("%Y-%m-%d %H:%M")
                break
        self._save()

    def skip(self, domain: str, reason: str = "") -> None:
        """Skip a target."""
        for t in self.targets:
            if t["domain"] == domain:
                t["status"] = f"skipped: {reason}"
                break
        self._save()

    def list_targets(self, status: str = "") -> list:
        """List targets, optionally filtered by status."""
        if status:
            return [t for t in self.targets if t["status"] == status]
        return self.targets

    def stats(self) -> dict:
        """Get queue statistics."""
        return {
            "total": len(self.targets),
            "queued": len([t for t in self.targets if t["status"] == "queued"]),
            "recon_done": len([t for t in self.targets if t["status"] == "recon_done"]),
            "completed": len([t for t in self.targets if t["status"] == "completed"]),
            "total_findings": sum(t.get("findings_count", 0) for t in self.targets),
        }

    def import_from_h1(self, programs: list) -> None:
        """Import multiple H1 programs into queue."""
        for p in programs:
            self.add(
                domain=p.get("domain", p.get("handle", "")),
                program=p.get("handle", ""),
                platform="hackerone",
                priority=p.get("priority", 5),
                max_bounty=p.get("max_bounty", 0),
            )
