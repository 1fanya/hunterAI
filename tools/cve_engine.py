#!/usr/bin/env python3
"""
cve_engine.py — Autonomous CVE/Exploit Lookup Engine

Detects software version → finds CVEs → finds exploits → auto-chains to exploitation.

Data sources:
  1. NVD API (NIST) — authoritative CVE data with CPE matching
  2. CISA KEV — actively exploited vulns (highest priority)
  3. searchsploit — local ExploitDB with PoC code
  4. Metasploit (via msf_adapter) — auto-exploit modules

Usage:
    from cve_engine import CVEEngine
    engine = CVEEngine()
    results = engine.lookup("Apache", "2.4.49")
    # → CVEs, exploits, KEV status, severity, PoC paths
"""
import json
import os
import re
import subprocess
import time
from pathlib import Path

try:
    import requests
except ImportError:
    requests = None


# ── CISA KEV cache ──────────────────────────────────────────────────────
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
KEV_CACHE = Path("hunt-memory/cve_cache/kev.json")

# ── NVD API ─────────────────────────────────────────────────────────────
NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_KEY = os.environ.get("NVD_API_KEY", "")  # Free key: 50 req/30s


class CVEEngine:
    """Autonomous CVE/exploit lookup engine."""

    def __init__(self, cache_dir: str = ""):
        self.cache_dir = Path(cache_dir) if cache_dir else Path("hunt-memory/cve_cache")
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.session = requests.Session() if requests else None
        if self.session:
            self.session.headers["User-Agent"] = "HunterAI-CVE-Engine/1.0"
            if NVD_KEY:
                self.session.headers["apiKey"] = NVD_KEY
        self.kev_data = self._load_kev()

    # ── NVD API lookup ──────────────────────────────────────────────────

    def search_nvd(self, keyword: str, version: str = "") -> list[dict]:
        """Search NVD for CVEs by product keyword and version."""
        if not self.session:
            return []

        query = f"{keyword} {version}".strip()
        params = {
            "keywordSearch": query,
            "resultsPerPage": 20,
        }

        try:
            resp = self.session.get(NVD_API, params=params, timeout=15)
            if resp.status_code == 403:
                # Rate limited — wait and retry
                time.sleep(6)
                resp = self.session.get(NVD_API, params=params, timeout=15)

            if resp.status_code != 200:
                return []

            data = resp.json()
            results = []

            for item in data.get("vulnerabilities", []):
                cve = item.get("cve", {})
                cve_id = cve.get("id", "")

                # Extract CVSS score
                metrics = cve.get("metrics", {})
                cvss_score = 0.0
                severity = "UNKNOWN"

                # Try CVSS 3.1 first, then 3.0, then 2.0
                for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                    metric_list = metrics.get(key, [])
                    if metric_list:
                        cvss_data = metric_list[0].get("cvssData", {})
                        cvss_score = cvss_data.get("baseScore", 0.0)
                        severity = cvss_data.get("baseSeverity",
                                    metric_list[0].get("baseSeverity", "UNKNOWN"))
                        break

                # Extract description
                descriptions = cve.get("descriptions", [])
                desc = ""
                for d in descriptions:
                    if d.get("lang") == "en":
                        desc = d.get("value", "")
                        break

                # Extract affected versions (CPE)
                affected = []
                configs = cve.get("configurations", [])
                for config in configs:
                    for node in config.get("nodes", []):
                        for match in node.get("cpeMatch", []):
                            if match.get("vulnerable"):
                                affected.append({
                                    "cpe": match.get("criteria", ""),
                                    "version_start": match.get("versionStartIncluding", ""),
                                    "version_end": match.get("versionEndIncluding",
                                                    match.get("versionEndExcluding", "")),
                                })

                # Check if version matches
                version_match = self._version_matches(version, affected) if version else True

                results.append({
                    "cve_id": cve_id,
                    "cvss": cvss_score,
                    "severity": severity,
                    "description": desc[:300],
                    "affected_versions": affected[:5],
                    "version_match": version_match,
                    "kev": self.is_kev(cve_id),
                    "references": [ref.get("url", "") for ref in
                                   cve.get("references", [])[:5]],
                })

            # Sort by CVSS (highest first), KEV prioritized
            results.sort(key=lambda x: (x["kev"], x["cvss"]), reverse=True)
            return results

        except Exception as e:
            return [{"error": str(e)}]

    def _version_matches(self, version: str, affected: list[dict]) -> bool:
        """Check if version falls within affected range."""
        if not version or not affected:
            return True  # Can't determine — assume possible

        for entry in affected:
            cpe = entry.get("cpe", "").lower()
            if version.lower() in cpe:
                return True
            # Check range
            v_start = entry.get("version_start", "")
            v_end = entry.get("version_end", "")
            if v_start and v_end:
                try:
                    from packaging.version import Version
                    v = Version(version)
                    if Version(v_start) <= v <= Version(v_end):
                        return True
                except Exception:
                    # Fallback: string comparison
                    if v_start <= version <= v_end:
                        return True
        return False

    # ── CISA KEV (Known Exploited Vulnerabilities) ──────────────────────

    def _load_kev(self) -> dict:
        """Load CISA KEV catalog (cache for 24h)."""
        if KEV_CACHE.exists():
            try:
                age = time.time() - KEV_CACHE.stat().st_mtime
                if age < 86400:  # 24 hours
                    data = json.loads(KEV_CACHE.read_text(encoding="utf-8"))
                    return {v["cveID"]: v for v in data.get("vulnerabilities", [])}
            except Exception:
                pass

        # Download fresh
        if self.session:
            try:
                resp = self.session.get(KEV_URL, timeout=15)
                if resp.status_code == 200:
                    data = resp.json()
                    KEV_CACHE.parent.mkdir(parents=True, exist_ok=True)
                    KEV_CACHE.write_text(json.dumps(data, indent=2),
                                         encoding="utf-8")
                    return {v["cveID"]: v for v in data.get("vulnerabilities", [])}
            except Exception:
                pass

        return {}

    def is_kev(self, cve_id: str) -> bool:
        """Check if CVE is in CISA KEV (actively exploited)."""
        return cve_id in self.kev_data

    def get_kev_details(self, cve_id: str) -> dict:
        """Get KEV details for a CVE."""
        return self.kev_data.get(cve_id, {})

    # ── searchsploit (ExploitDB) ────────────────────────────────────────

    def search_exploitdb(self, query: str) -> list[dict]:
        """Search local ExploitDB via searchsploit."""
        try:
            result = subprocess.run(
                ["searchsploit", query, "--json"],
                capture_output=True, text=True, timeout=30)

            if result.returncode != 0 or not result.stdout.strip():
                return []

            data = json.loads(result.stdout)
            exploits = []

            for exp in data.get("RESULTS_EXPLOIT", []):
                exploits.append({
                    "title": exp.get("Title", ""),
                    "edb_id": exp.get("EDB-ID", ""),
                    "path": exp.get("Path", ""),
                    "platform": exp.get("Platform", ""),
                    "type": exp.get("Type", ""),
                    "date": exp.get("Date Published", ""),
                })

            return exploits

        except FileNotFoundError:
            return [{"error": "searchsploit not installed (apt install exploitdb)"}]
        except Exception as e:
            return [{"error": str(e)}]

    def search_exploitdb_by_cve(self, cve_id: str) -> list[dict]:
        """Search ExploitDB specifically by CVE ID."""
        return self.search_exploitdb(cve_id)

    # ── Metasploit search ───────────────────────────────────────────────

    def search_metasploit(self, cve_id: str) -> list[dict]:
        """Search Metasploit for modules matching a CVE."""
        try:
            cmd = f'search cve:{cve_id} -o /tmp/msf_search.txt; cat /tmp/msf_search.txt; exit'
            result = subprocess.run(
                ["msfconsole", "-q", "-x", cmd],
                capture_output=True, text=True, timeout=60)

            output = result.stdout
            modules = []

            # Parse msfconsole search output
            for line in output.split("\n"):
                line = line.strip()
                if not line or line.startswith("#") or line.startswith("="):
                    continue

                # Match exploit/auxiliary/post modules
                match = re.match(
                    r'\s*\d+\s+(exploit|auxiliary|post)/(\S+)\s+'
                    r'(\d{4}-\d{2}-\d{2})?\s*(.*)',
                    line)
                if match:
                    mod_type = match.group(1)
                    mod_path = f"{mod_type}/{match.group(2)}"
                    modules.append({
                        "module": mod_path,
                        "type": mod_type,
                        "name": match.group(4).strip() if match.group(4) else "",
                        "date": match.group(3) or "",
                    })

            return modules

        except FileNotFoundError:
            return [{"error": "msfconsole not installed"}]
        except subprocess.TimeoutExpired:
            return [{"error": "msfconsole search timed out"}]
        except Exception as e:
            return [{"error": str(e)}]

    # ── High-Level Lookup (combines all sources) ────────────────────────

    def lookup(self, product: str, version: str = "") -> dict:
        """
        Full lookup: product/version → CVEs → exploits → KEV status.

        Usage:
            result = engine.lookup("Apache httpd", "2.4.49")
            result = engine.lookup("nginx", "1.18.0")
            result = engine.lookup("WordPress", "5.8.1")
        """
        query = f"{product} {version}".strip()

        result = {
            "product": product,
            "version": version,
            "cves": [],
            "exploits": [],
            "metasploit_modules": [],
            "kev_matches": [],
            "highest_cvss": 0.0,
            "exploitable": False,
            "summary": "",
        }

        # Step 1: NVD CVE lookup
        cves = self.search_nvd(product, version)
        result["cves"] = [c for c in cves if not c.get("error")]

        if result["cves"]:
            result["highest_cvss"] = max(c.get("cvss", 0) for c in result["cves"])

        # Step 2: ExploitDB search
        exploits = self.search_exploitdb(query)
        result["exploits"] = [e for e in exploits if not e.get("error")]

        # Step 3: For top CVEs, search ExploitDB and Metasploit by CVE
        top_cves = [c for c in result["cves"] if c.get("cvss", 0) >= 7.0][:5]

        for cve in top_cves:
            cve_id = cve["cve_id"]

            # ExploitDB by CVE
            edb = self.search_exploitdb_by_cve(cve_id)
            for e in edb:
                if not e.get("error") and e not in result["exploits"]:
                    e["cve"] = cve_id
                    result["exploits"].append(e)

            # Metasploit by CVE
            msf = self.search_metasploit(cve_id)
            for m in msf:
                if not m.get("error"):
                    m["cve"] = cve_id
                    result["metasploit_modules"].append(m)

            # KEV check
            if self.is_kev(cve_id):
                kev = self.get_kev_details(cve_id)
                result["kev_matches"].append({
                    "cve": cve_id,
                    "product": kev.get("product", ""),
                    "required_action": kev.get("requiredAction", ""),
                    "due_date": kev.get("dueDate", ""),
                })

        # Determine if exploitable
        result["exploitable"] = bool(
            result["exploits"] or result["metasploit_modules"])

        # Summary
        n_cves = len(result["cves"])
        n_exploits = len(result["exploits"])
        n_msf = len(result["metasploit_modules"])
        n_kev = len(result["kev_matches"])

        parts = [f"{n_cves} CVEs found"]
        if n_exploits:
            parts.append(f"{n_exploits} ExploitDB entries")
        if n_msf:
            parts.append(f"{n_msf} Metasploit modules")
        if n_kev:
            parts.append(f"{n_kev} CISA KEV (actively exploited!)")
        parts.append(f"Highest CVSS: {result['highest_cvss']}")

        result["summary"] = " | ".join(parts)

        return result

    # ── Version detection helper (from HTTP headers/responses) ──────────

    @staticmethod
    def extract_versions(text: str) -> list[dict]:
        """Extract product/version pairs from text (HTTP headers, HTML, etc.)."""
        patterns = [
            # Server: Apache/2.4.49
            (r'(?:Server|X-Powered-By):\s*(\S+?)/([\d.]+)', "header"),
            # Apache/2.4.49 (Unix)
            (r'(Apache|nginx|Microsoft-IIS|lighttpd|LiteSpeed)/([\d.]+)', "server"),
            # PHP/7.4.3
            (r'(PHP|Python|Ruby|Java|ASP\.NET)/([\d.]+)', "language"),
            # WordPress 5.8.1
            (r'(WordPress|Drupal|Joomla|Magento|Laravel|Django|Rails)\s*[/:]?\s*([\d.]+)', "cms"),
            # jQuery v3.6.0
            (r'(jQuery|React|Angular|Vue|Bootstrap|Express)\s*[v/]?\s*([\d.]+)', "js_lib"),
            # OpenSSH_8.2p1
            (r'(OpenSSH)[_/]([\d.p]+)', "service"),
            # vsftpd 3.0.3
            (r'(vsftpd|ProFTPD|Pure-FTPd)\s+([\d.]+)', "service"),
            # MySQL/5.7.33
            (r'(MySQL|MariaDB|PostgreSQL|MongoDB|Redis)\s*[/:]?\s*([\d.]+)', "database"),
            # Tomcat/9.0.50
            (r'(Tomcat|Jetty|WildFly|GlassFish)\s*[/:]?\s*([\d.]+)', "app_server"),
        ]

        found = []
        seen = set()

        for pattern, category in patterns:
            for match in re.finditer(pattern, text, re.IGNORECASE):
                product = match.group(1)
                version = match.group(2)
                key = f"{product.lower()}/{version}"
                if key not in seen:
                    seen.add(key)
                    found.append({
                        "product": product,
                        "version": version,
                        "category": category,
                    })

        return found

    # ── Save results ────────────────────────────────────────────────────

    def save_results(self, target: str, results: dict) -> None:
        """Save CVE lookup results."""
        out_dir = Path(f"findings/{target}/cve")
        out_dir.mkdir(parents=True, exist_ok=True)
        out_file = out_dir / f"cve_scan_{int(time.time())}.json"
        out_file.write_text(json.dumps(results, indent=2, default=str),
                            encoding="utf-8")


# ── CLI test ────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import sys

    engine = CVEEngine()

    if len(sys.argv) >= 3:
        product = sys.argv[1]
        version = sys.argv[2]
    elif "--test" in sys.argv:
        product = "Apache httpd"
        version = "2.4.49"
    else:
        print("Usage: python3 cve_engine.py <product> <version>")
        print("       python3 cve_engine.py --test")
        sys.exit(1)

    print(f"\n[CVE] Looking up: {product} {version}")
    print("=" * 60)

    result = engine.lookup(product, version)
    print(f"\n{result['summary']}\n")

    if result["cves"]:
        print("CVEs:")
        for cve in result["cves"][:10]:
            kev_tag = " [CISA KEV!]" if cve.get("kev") else ""
            print(f"  {cve['cve_id']}  CVSS {cve['cvss']}  "
                  f"{cve['severity']}{kev_tag}")
            print(f"    {cve['description'][:120]}...")

    if result["exploits"]:
        print(f"\nExploitDB ({len(result['exploits'])}):")
        for exp in result["exploits"][:5]:
            print(f"  [{exp.get('edb_id', '?')}] {exp.get('title', '?')}")
            print(f"    Path: {exp.get('path', '?')}")

    if result["metasploit_modules"]:
        print(f"\nMetasploit ({len(result['metasploit_modules'])}):")
        for mod in result["metasploit_modules"][:5]:
            print(f"  {mod['module']}")

    if result["kev_matches"]:
        print(f"\n⚠ CISA KEV — Actively Exploited:")
        for kev in result["kev_matches"]:
            print(f"  {kev['cve']} — {kev.get('required_action', '')[:80]}")

    print(f"\nExploitable: {'YES' if result['exploitable'] else 'No'}")
