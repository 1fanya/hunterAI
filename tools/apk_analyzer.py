#!/usr/bin/env python3
"""
apk_analyzer.py — Android APK Decompiler & Endpoint Extractor

Decompiles APKs to find hardcoded API keys, hidden endpoints,
certificate pinning configs, and internal URLs.

Usage:
    from apk_analyzer import APKAnalyzer
    analyzer = APKAnalyzer()
    results = analyzer.analyze("app.apk")
"""
import json
import os
import re
import subprocess
import time
from pathlib import Path


class APKAnalyzer:
    """APK reverse engineering for bug bounty hunting."""

    SECRET_PATTERNS = [
        (r'(?:api[_-]?key|apikey)\s*[:=]\s*["\']([^"\']{10,})["\']', "API Key"),
        (r'(?:aws_access_key|AKIA)[A-Z0-9]{16,}', "AWS Key"),
        (r'(?:ghp_|github_pat_)[A-Za-z0-9_]{36,}', "GitHub Token"),
        (r'(?:firebase|firebaseio)\.com/[^\s"\']+', "Firebase URL"),
        (r'(?:maps\.googleapis|maps\.google)\.com[^\s"\']*key=([^\s"\'&]+)', "Google Maps Key"),
        (r'(?:sk_live_|pk_live_)[A-Za-z0-9]{20,}', "Stripe Key"),
        (r'https?://[^\s"\']*\.(?:s3|s3-\w+)\.amazonaws\.com[^\s"\']*', "S3 URL"),
        (r'eyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*', "JWT"),
        (r'(?:mongodb|postgres|mysql|redis)://[^\s"\']+', "DB URL"),
    ]

    URL_PATTERNS = [
        r'https?://[a-zA-Z0-9._-]+\.[a-zA-Z]{2,}(?:/[^\s"\'<>]*)?',
    ]

    def __init__(self):
        self.apktool = self._check_tool("apktool")
        self.jadx = self._check_tool("jadx")

    @staticmethod
    def _check_tool(name: str) -> bool:
        try:
            subprocess.run([name, "--version"], capture_output=True, timeout=10)
            return True
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return False

    def decompile(self, apk_path: str) -> str:
        """Decompile APK and return output directory."""
        out_dir = Path(apk_path).stem + "_decompiled"

        if self.jadx:
            subprocess.run(
                ["jadx", "-d", out_dir, apk_path],
                capture_output=True, timeout=300)
        elif self.apktool:
            subprocess.run(
                ["apktool", "d", apk_path, "-o", out_dir, "-f"],
                capture_output=True, timeout=300)
        else:
            return ""

        return out_dir if Path(out_dir).exists() else ""

    def analyze(self, apk_path: str) -> dict:
        """Full APK analysis: decompile, extract secrets, endpoints, configs."""
        result = {
            "apk": apk_path,
            "endpoints": [],
            "secrets": [],
            "urls": set(),
            "network_config": {},
            "permissions": [],
        }

        out_dir = self.decompile(apk_path)
        if not out_dir:
            # Try strings-only analysis
            return self._strings_analysis(apk_path)

        out_path = Path(out_dir)

        # Scan all source files
        for ext in ("*.java", "*.kt", "*.xml", "*.json", "*.properties",
                     "*.smali", "*.yml", "*.yaml"):
            for f in out_path.rglob(ext):
                try:
                    content = f.read_text(encoding="utf-8", errors="ignore")
                    self._extract_from_content(content, str(f), result)
                except Exception:
                    continue

        # Check AndroidManifest.xml
        manifest = out_path / "AndroidManifest.xml"
        if manifest.exists():
            self._parse_manifest(manifest.read_text(encoding="utf-8",
                                                      errors="ignore"), result)

        # Check network_security_config.xml
        for nsc in out_path.rglob("network_security_config.xml"):
            content = nsc.read_text(encoding="utf-8", errors="ignore")
            result["network_config"] = self._parse_network_config(content)

        result["urls"] = sorted(result["urls"])
        return result

    def _strings_analysis(self, apk_path: str) -> dict:
        """Fallback: extract strings from APK without decompilation."""
        result = {"apk": apk_path, "endpoints": [], "secrets": [],
                  "urls": set()}
        try:
            proc = subprocess.run(["strings", apk_path],
                                   capture_output=True, text=True, timeout=60)
            self._extract_from_content(proc.stdout, apk_path, result)
        except Exception:
            pass
        result["urls"] = sorted(result["urls"])
        return result

    def _extract_from_content(self, content: str, source: str, result: dict):
        """Extract secrets and URLs from content."""
        # Secrets
        for pattern, label in self.SECRET_PATTERNS:
            for m in re.finditer(pattern, content, re.IGNORECASE):
                val = m.group(1) if m.lastindex else m.group(0)
                result["secrets"].append({
                    "type": label, "value": val[:80], "source": source,
                })

        # URLs
        for pattern in self.URL_PATTERNS:
            for m in re.finditer(pattern, content):
                url = m.group(0)
                if not any(skip in url for skip in
                          ("google.com/", "android.com/", "apache.org/",
                           "w3.org/", "schema.org/", "xml.org/", "github.com/")):
                    result["urls"].add(url)

        # API endpoints
        for m in re.finditer(r'["\']/(api|v\d|graphql|rest)/[^"\']+["\']', content):
            result["endpoints"].append(m.group(0).strip("\"'"))

    def _parse_manifest(self, content: str, result: dict):
        """Parse AndroidManifest.xml for permissions and components."""
        for m in re.finditer(r'android:name="([^"]*permission[^"]*)"',
                             content, re.IGNORECASE):
            result["permissions"].append(m.group(1))

        # Check for exported components (potential attack surface)
        for m in re.finditer(
                r'android:exported="true"[^>]*android:name="([^"]+)"', content):
            result.setdefault("exported_components", []).append(m.group(1))

    @staticmethod
    def _parse_network_config(content: str) -> dict:
        """Parse network_security_config.xml."""
        config = {
            "cleartext_allowed": "cleartextTrafficPermitted=\"true\"" in content,
            "custom_trust_anchors": "trust-anchors" in content,
            "pin_set": "pin-set" in content,
        }
        return config
