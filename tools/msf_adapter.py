#!/usr/bin/env python3
"""
msf_adapter.py — Metasploit Framework CLI Adapter

Fire-and-forget exploit execution via msfconsole CLI.
No msfrpcd dependency — works with any Kali install.

Usage:
    from msf_adapter import MetasploitAdapter
    msf = MetasploitAdapter()
    modules = msf.search("cve:2021-41773")
    result = msf.run_exploit("exploit/multi/http/apache_normalize_path_rce",
                             target="10.0.0.1", options={"RPORT": 443})
"""
import json
import os
import re
import subprocess
import time
from pathlib import Path


class MetasploitAdapter:
    """CLI adapter for Metasploit Framework."""

    def __init__(self, timeout: int = 120):
        self.timeout = timeout
        self.available = self._check_installed()

    def _check_installed(self) -> bool:
        """Check if msfconsole is available."""
        try:
            result = subprocess.run(
                ["msfconsole", "--version"],
                capture_output=True, text=True, timeout=10)
            return result.returncode == 0
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return False

    def _run_msf_command(self, command: str, timeout: int = None) -> str:
        """Execute a command in msfconsole and return output."""
        timeout = timeout or self.timeout
        try:
            result = subprocess.run(
                ["msfconsole", "-q", "-x", f"{command}; exit"],
                capture_output=True, text=True, timeout=timeout)
            return result.stdout
        except FileNotFoundError:
            return "ERROR: msfconsole not found"
        except subprocess.TimeoutExpired:
            return "ERROR: command timed out"

    def search(self, query: str) -> list[dict]:
        """Search for Metasploit modules.

        Args:
            query: Search query (e.g., "cve:2021-41773", "type:exploit apache")
        """
        if not self.available:
            return [{"error": "msfconsole not installed"}]

        output = self._run_msf_command(f"search {query}")
        return self._parse_search_output(output)

    def _parse_search_output(self, output: str) -> list[dict]:
        """Parse msfconsole search output into structured data."""
        modules = []

        for line in output.split("\n"):
            line = line.strip()
            if not line:
                continue

            # Match module lines: "  0  exploit/path/name  date  rank  check  description"
            match = re.match(
                r'\s*(\d+)\s+'
                r'(exploit|auxiliary|post|payload|encoder|nop)/(\S+)\s+'
                r'(\d{4}-\d{2}-\d{2})?\s*'
                r'(excellent|great|good|normal|average|low|manual)?\s*'
                r'(Yes|No)?\s*'
                r'(.*)',
                line)

            if match:
                mod_type = match.group(2)
                mod_path = match.group(3)
                modules.append({
                    "module": f"{mod_type}/{mod_path}",
                    "type": mod_type,
                    "date": match.group(4) or "",
                    "rank": match.group(5) or "",
                    "check": match.group(6) == "Yes" if match.group(6) else False,
                    "name": match.group(7).strip() if match.group(7) else "",
                })

        return modules

    def get_module_info(self, module_path: str) -> dict:
        """Get detailed info about a Metasploit module."""
        if not self.available:
            return {"error": "msfconsole not installed"}

        output = self._run_msf_command(f"info {module_path}")

        info = {"module": module_path, "raw_output": output}

        # Parse key fields
        for field in ("Name", "Module", "Platform", "Arch", "Rank",
                       "Description"):
            match = re.search(rf'{field}:\s+(.+)', output)
            if match:
                info[field.lower()] = match.group(1).strip()

        # Parse options
        options = []
        in_options = False
        for line in output.split("\n"):
            if "Name" in line and "Required" in line and "Description" in line:
                in_options = True
                continue
            if in_options:
                if line.strip() == "" or line.startswith("   -"):
                    in_options = False
                    continue
                parts = line.split()
                if len(parts) >= 3:
                    options.append({
                        "name": parts[0],
                        "required": parts[1] == "yes",
                        "current": parts[2] if len(parts) > 2 else "",
                        "description": " ".join(parts[3:]) if len(parts) > 3 else "",
                    })

        info["options"] = options
        return info

    def run_exploit(self, module_path: str, target: str,
                    options: dict = None, payload: str = "") -> dict:
        """
        Run a Metasploit exploit module.

        Args:
            module_path: e.g., "exploit/multi/http/apache_normalize_path_rce"
            target: Target IP or hostname
            options: Dict of module options (e.g., {"RPORT": 443, "SSL": True})
            payload: Optional payload (e.g., "cmd/unix/reverse_bash")
        """
        if not self.available:
            return {"error": "msfconsole not installed", "success": False}

        # Build command sequence
        commands = [f"use {module_path}"]

        # Set target
        commands.append(f"set RHOSTS {target}")
        commands.append(f"set RHOST {target}")

        # Set payload if specified
        if payload:
            commands.append(f"set PAYLOAD {payload}")

        # Set additional options
        if options:
            for key, value in options.items():
                commands.append(f"set {key} {value}")

        # Use check first if available (non-destructive)
        commands.append("check")

        cmd_str = "; ".join(commands)

        result = {
            "module": module_path,
            "target": target,
            "success": False,
            "output": "",
            "vulnerable": False,
        }

        try:
            output = self._run_msf_command(cmd_str, timeout=self.timeout)
            result["output"] = output

            # Check for vulnerability confirmation
            if "is vulnerable" in output.lower():
                result["vulnerable"] = True
                result["success"] = True
            elif "appears to be vulnerable" in output.lower():
                result["vulnerable"] = True
                result["success"] = True
            elif "session" in output.lower() and "opened" in output.lower():
                result["success"] = True
                result["vulnerable"] = True

        except Exception as e:
            result["error"] = str(e)

        return result

    def check_vuln(self, module_path: str, target: str,
                   options: dict = None) -> dict:
        """Check if target is vulnerable (non-destructive)."""
        return self.run_exploit(module_path, target, options)

    def save_results(self, target: str, results: list[dict]) -> None:
        """Save MSF results."""
        out_dir = Path(f"findings/{target}/metasploit")
        out_dir.mkdir(parents=True, exist_ok=True)
        out_file = out_dir / f"msf_{int(time.time())}.json"
        out_file.write_text(json.dumps(results, indent=2, default=str),
                            encoding="utf-8")
