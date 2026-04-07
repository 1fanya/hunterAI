#!/usr/bin/env python3
"""
telegram_notifier.py — Real-time Telegram alerts for findings.

Get instant notifications on your phone when a vulnerability is found.

Setup:
    1. Talk to @BotFather on Telegram, create bot, get token
    2. Get your chat_id from @userinfobot
    3. Set env: TELEGRAM_BOT_TOKEN, TELEGRAM_CHAT_ID

Usage:
    from telegram_notifier import TelegramNotifier
    notifier = TelegramNotifier()
    notifier.finding_alert(finding_dict)
"""
import json
import os
import time

try:
    import requests
except ImportError:
    requests = None


class TelegramNotifier:
    """Telegram bot for real-time bug bounty alerts."""

    def __init__(self, bot_token: str = "", chat_id: str = ""):
        self.token = bot_token or os.environ.get("TELEGRAM_BOT_TOKEN", "")
        self.chat_id = chat_id or os.environ.get("TELEGRAM_CHAT_ID", "")
        self.enabled = bool(self.token and self.chat_id)
        self.api = f"https://api.telegram.org/bot{self.token}" if self.token else ""

    def send(self, message: str, parse_mode: str = "HTML") -> bool:
        """Send a message via Telegram."""
        if not self.enabled or not requests:
            return False
        try:
            resp = requests.post(f"{self.api}/sendMessage", json={
                "chat_id": self.chat_id,
                "text": message[:4096],
                "parse_mode": parse_mode,
                "disable_web_page_preview": True,
            }, timeout=10)
            return resp.status_code == 200
        except Exception:
            return False

    def finding_alert(self, finding: dict) -> bool:
        """Alert about a validated finding."""
        severity = finding.get("severity", "MEDIUM")
        emoji = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡",
                 "LOW": "🟢"}.get(severity, "⚪")

        msg = (
            f"{emoji} <b>FINDING: {severity}</b>\n\n"
            f"<b>Type:</b> {finding.get('vuln_class', finding.get('type', 'Unknown'))}\n"
            f"<b>Target:</b> {finding.get('url', finding.get('endpoint', 'N/A'))}\n"
            f"<b>CVSS:</b> {finding.get('cvss', 'N/A')}\n"
        )

        if finding.get("cve_id"):
            msg += f"<b>CVE:</b> {finding['cve_id']}\n"
        if finding.get("description"):
            msg += f"\n{finding['description'][:200]}\n"
        if finding.get("kev"):
            msg += "\n⚠️ <b>CISA KEV - Actively Exploited!</b>\n"

        msg += f"\n<i>HunterAI — {time.strftime('%Y-%m-%d %H:%M')}</i>"
        return self.send(msg)

    def hunt_started(self, target: str, program: str = "") -> bool:
        msg = f"🎯 <b>Hunt Started</b>\nTarget: {target}"
        if program:
            msg += f"\nProgram: {program}"
        return self.send(msg)

    def hunt_completed(self, target: str, findings_count: int,
                       duration: str = "") -> bool:
        msg = (f"✅ <b>Hunt Complete</b>\n"
               f"Target: {target}\n"
               f"Findings: {findings_count}")
        if duration:
            msg += f"\nDuration: {duration}"
        return self.send(msg)

    def cve_alert(self, product: str, version: str, cve_id: str,
                  cvss: float, kev: bool = False) -> bool:
        emoji = "🔴" if cvss >= 9.0 else "🟠" if cvss >= 7.0 else "🟡"
        msg = (f"{emoji} <b>CVE Found</b>\n"
               f"{cve_id} (CVSS {cvss})\n"
               f"{product} {version}")
        if kev:
            msg += "\n⚠️ CISA KEV!"
        return self.send(msg)

    def error_alert(self, message: str) -> bool:
        return self.send(f"❌ <b>Error:</b> {message}")
