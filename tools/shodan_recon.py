#!/usr/bin/env python3
"""
shodan_recon.py — Shodan Passive Reconnaissance

Query Shodan for exposed services, open ports, tech fingerprints,
and known vulnerabilities — without touching the target.

Usage:
    from shodan_recon import ShodanRecon
    sr = ShodanRecon()
    results = sr.host_info("93.184.216.34")
    results = sr.domain_search("target.com")
"""
import json
import os
import time
from pathlib import Path

try:
    import requests
except ImportError:
    requests = None

SHODAN_API = "https://api.shodan.io"
# Free InternetDB (no API key needed)
INTERNETDB = "https://internetdb.shodan.io"


class ShodanRecon:
    """Shodan passive scanner — zero interaction with target."""

    def __init__(self, api_key: str = ""):
        self.api_key = api_key or os.environ.get("SHODAN_API_KEY", "")
        self.session = requests.Session() if requests else None
        if self.session:
            self.session.headers["User-Agent"] = "HunterAI/1.0"

    def internetdb_lookup(self, ip: str) -> dict:
        """Free InternetDB lookup — no API key needed.
        Returns ports, hostnames, vulns, tags, CPEs."""
        if not self.session:
            return {"error": "requests not available"}
        try:
            resp = self.session.get(f"{INTERNETDB}/{ip}", timeout=10)
            if resp.status_code == 200:
                return resp.json()
            return {"error": f"HTTP {resp.status_code}"}
        except Exception as e:
            return {"error": str(e)}

    def host_info(self, ip: str) -> dict:
        """Get host info from Shodan (requires API key)."""
        if not self.api_key:
            return self.internetdb_lookup(ip)
        try:
            resp = self.session.get(f"{SHODAN_API}/shodan/host/{ip}",
                                    params={"key": self.api_key}, timeout=15)
            if resp.status_code == 200:
                data = resp.json()
                return {
                    "ip": ip,
                    "hostnames": data.get("hostnames", []),
                    "ports": data.get("ports", []),
                    "os": data.get("os", ""),
                    "org": data.get("org", ""),
                    "vulns": data.get("vulns", []),
                    "tags": data.get("tags", []),
                    "services": [{
                        "port": s.get("port"),
                        "transport": s.get("transport", "tcp"),
                        "product": s.get("product", ""),
                        "version": s.get("version", ""),
                        "banner": s.get("data", "")[:200],
                    } for s in data.get("data", [])[:20]],
                }
            return {"error": f"HTTP {resp.status_code}"}
        except Exception as e:
            return {"error": str(e)}

    def domain_search(self, domain: str) -> dict:
        """Search Shodan for a domain (requires API key)."""
        if not self.api_key:
            # Fallback: resolve domain and use InternetDB
            return self._fallback_domain(domain)
        try:
            resp = self.session.get(f"{SHODAN_API}/dns/domain/{domain}",
                                    params={"key": self.api_key}, timeout=15)
            if resp.status_code != 200:
                return {"error": f"HTTP {resp.status_code}"}
            data = resp.json()
            return {
                "domain": domain,
                "subdomains": [f"{s}.{domain}" for s in data.get("subdomains", [])],
                "records": data.get("data", [])[:50],
            }
        except Exception as e:
            return {"error": str(e)}

    def _fallback_domain(self, domain: str) -> dict:
        """Resolve domain IPs and use free InternetDB."""
        import socket
        try:
            ips = set()
            for info in socket.getaddrinfo(domain, None):
                ips.add(info[4][0])

            results = {"domain": domain, "hosts": []}
            for ip in list(ips)[:5]:
                info = self.internetdb_lookup(ip)
                if not info.get("error"):
                    info["ip_address"] = ip
                    results["hosts"].append(info)

            return results
        except Exception as e:
            return {"error": str(e)}

    def search(self, query: str) -> list:
        """General Shodan search (requires API key)."""
        if not self.api_key:
            return [{"error": "API key required for search"}]
        try:
            resp = self.session.get(f"{SHODAN_API}/shodan/host/search",
                                    params={"key": self.api_key, "query": query},
                                    timeout=15)
            if resp.status_code != 200:
                return [{"error": f"HTTP {resp.status_code}"}]
            return resp.json().get("matches", [])[:20]
        except Exception as e:
            return [{"error": str(e)}]

    def find_vulns(self, ip: str) -> list:
        """Get known vulnerabilities for an IP."""
        info = self.internetdb_lookup(ip)
        if info.get("error"):
            return []
        return info.get("vulns", [])

    def find_exposed_services(self, domain: str) -> list:
        """Find interesting exposed services (DB, admin panels, etc.)."""
        result = self.domain_search(domain)
        interesting = []
        dangerous_ports = {
            21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
            3306: "MySQL", 5432: "PostgreSQL", 6379: "Redis",
            27017: "MongoDB", 9200: "Elasticsearch", 5601: "Kibana",
            8080: "HTTP-Alt", 8443: "HTTPS-Alt", 9090: "Admin",
            2375: "Docker", 2376: "Docker-TLS", 5900: "VNC",
            11211: "Memcached", 1433: "MSSQL", 1521: "Oracle",
        }
        for host in result.get("hosts", []):
            for port in host.get("ports", []):
                if port in dangerous_ports:
                    interesting.append({
                        "ip": host.get("ip_address", host.get("ip", "")),
                        "port": port,
                        "service": dangerous_ports[port],
                        "severity": "HIGH" if port in (3306, 5432, 6379, 27017, 2375) else "MEDIUM",
                    })
        return interesting

    def save_results(self, target: str, data: dict):
        out = Path(f"findings/{target}/shodan")
        out.mkdir(parents=True, exist_ok=True)
        (out / f"shodan_{int(time.time())}.json").write_text(
            json.dumps(data, indent=2, default=str), encoding="utf-8")
