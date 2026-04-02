#!/usr/bin/env python3
"""
api_discovery.py — API Documentation & Endpoint Discovery

Finds Swagger/OpenAPI, Postman, WADL, WSDL, and GraphQL docs.
Finding API docs = instant map of every endpoint, parameter, and model.

Usage:
    from api_discovery import APIDiscovery
    disco = APIDiscovery("https://target.com")
    results = disco.discover()
"""
import json
import os
import re
import time
from pathlib import Path
from urllib.parse import urlparse, urljoin

try:
    import requests
except ImportError:
    requests = None

# ── Discovery paths ────────────────────────────────────────────────────────────

SWAGGER_PATHS = [
    "/swagger.json", "/swagger/v1/swagger.json", "/swagger/v2/swagger.json",
    "/api-docs", "/api-docs.json", "/api/swagger.json",
    "/v1/swagger.json", "/v2/swagger.json", "/v3/swagger.json",
    "/openapi.json", "/openapi.yaml", "/openapi/v3/api-docs",
    "/api/v1/swagger.json", "/api/v2/swagger.json",
    "/swagger-ui.html", "/swagger-ui/", "/swagger-resources",
    "/api/docs", "/api/documentation", "/docs/api",
    "/api/spec", "/api/schema",
    "/.well-known/openapi.json", "/.well-known/openapi.yaml",
]

POSTMAN_PATHS = [
    "/postman", "/postman_collection.json",
    "/api/postman", "/docs/postman",
    "/.postman/collection.json",
]

GRAPHQL_PATHS = [
    "/graphql", "/graphiql", "/api/graphql",
    "/v1/graphql", "/v2/graphql",
    "/playground", "/explorer",
    "/api/v1/graphql", "/api/v2/graphql",
]

OTHER_PATHS = [
    "/api", "/api/", "/api/v1", "/api/v2", "/api/v3",
    "/rest", "/rest/api",
    "/_api", "/__api",
    "/api/health", "/api/status", "/api/version",
    "/api/info", "/actuator", "/actuator/env",
    "/debug", "/debug/vars", "/debug/pprof",
    "/.env", "/config.json", "/app-config.json",
    "/robots.txt", "/sitemap.xml",
    "/wp-json/", "/wp-json/wp/v2/users",
    "/api/users", "/api/admin",
]

WADL_PATHS = [
    "/application.wadl", "/api/application.wadl",
]

WSDL_PATHS = [
    "/service?wsdl", "/ws?wsdl", "/api?wsdl",
    "/services?wsdl", "/soap?wsdl",
]


class APIDiscovery:
    """Discover API documentation and hidden endpoints."""

    def __init__(self, base_url: str = ""):
        self.base_url = base_url.rstrip("/")
        self.findings = []
        self.endpoints = []
        self.session = requests.Session() if requests else None
        if self.session:
            self.session.verify = False
            import urllib3
            urllib3.disable_warnings()

    def probe_path(self, path: str, headers: dict = None) -> dict:
        """Probe a single path for content."""
        headers = headers or {}
        url = f"{self.base_url}{path}"

        try:
            resp = self.session.get(url, headers=headers, timeout=8,
                                   allow_redirects=True)
            if resp.status_code == 200 and len(resp.text) > 50:
                content_type = resp.headers.get("Content-Type", "")
                return {
                    "url": url,
                    "path": path,
                    "status": resp.status_code,
                    "content_type": content_type,
                    "length": len(resp.text),
                    "body_preview": resp.text[:500],
                }
        except Exception:
            pass

        return {}

    def discover_swagger(self, headers: dict = None) -> list[dict]:
        """Find Swagger/OpenAPI documentation."""
        found = []
        for path in SWAGGER_PATHS:
            result = self.probe_path(path, headers)
            if result:
                body = result.get("body_preview", "")
                if any(k in body for k in
                       ("swagger", "openapi", "paths", "info",
                        "ApiController", "basePath")):
                    result["type"] = "swagger"
                    result["severity"] = "MEDIUM"

                    # Try to parse endpoints
                    try:
                        url = result["url"]
                        resp = self.session.get(url, headers=headers, timeout=10)
                        spec = resp.json()
                        paths = spec.get("paths", {})
                        result["endpoint_count"] = len(paths)
                        result["endpoints"] = list(paths.keys())[:30]
                        self.endpoints.extend(paths.keys())
                    except Exception:
                        pass

                    found.append(result)
                    self.findings.append(result)

            time.sleep(0.2)
        return found

    def discover_graphql(self, headers: dict = None) -> list[dict]:
        """Find GraphQL endpoints."""
        found = []
        test_query = {"query": "{__typename}"}

        for path in GRAPHQL_PATHS:
            url = f"{self.base_url}{path}"
            try:
                resp = self.session.post(url, json=test_query,
                                        headers=headers, timeout=5)
                if resp.status_code == 200:
                    body = resp.text
                    if any(k in body for k in
                           ("__typename", "data", "errors", "graphql")):
                        result = {
                            "url": url, "type": "graphql",
                            "status": resp.status_code,
                            "severity": "MEDIUM",
                        }

                        # Test introspection
                        intro_resp = self.session.post(
                            url, json={"query": "{__schema{types{name}}}"},
                            headers=headers, timeout=8)
                        if intro_resp.status_code == 200 and "__schema" in intro_resp.text:
                            result["introspection"] = True
                            result["severity"] = "HIGH"

                        found.append(result)
                        self.findings.append(result)
            except Exception:
                continue

            time.sleep(0.2)
        return found

    def discover_postman(self, headers: dict = None) -> list[dict]:
        """Find Postman collections."""
        found = []
        for path in POSTMAN_PATHS:
            result = self.probe_path(path, headers)
            if result:
                body = result.get("body_preview", "")
                if any(k in body for k in
                       ("postman", "collection", "item", "request")):
                    result["type"] = "postman"
                    result["severity"] = "MEDIUM"
                    found.append(result)
                    self.findings.append(result)
            time.sleep(0.2)
        return found

    def discover_debug_endpoints(self, headers: dict = None) -> list[dict]:
        """Find debug/admin/config endpoints."""
        found = []
        for path in OTHER_PATHS:
            result = self.probe_path(path, headers)
            if result:
                body = result.get("body_preview", "")
                # Filter out generic 200 pages
                if len(body) < 100:
                    continue

                result["type"] = "endpoint"

                # Check for sensitive info
                sensitive_markers = [
                    "password", "secret", "api_key", "database",
                    "AWS_", "MYSQL_", "REDIS_", "MONGO_",
                    "stack trace", "exception", "debug",
                    "actuator", "admin",
                ]
                for marker in sensitive_markers:
                    if marker.lower() in body.lower():
                        result["sensitive"] = True
                        result["severity"] = "HIGH"
                        result["marker"] = marker
                        break

                if result.get("sensitive"):
                    found.append(result)
                    self.findings.append(result)

            time.sleep(0.2)
        return found

    def extract_endpoints_from_js(self, headers: dict = None) -> list[str]:
        """Extract API endpoints from JavaScript files."""
        endpoints = set()

        # Get main page
        try:
            resp = self.session.get(self.base_url, headers=headers, timeout=10)

            # Find JS files
            js_urls = re.findall(
                r'(?:src|href)=["\']([^"\']*\.js[^"\']*)["\']', resp.text)

            for js_url in js_urls[:10]:
                full_url = urljoin(self.base_url, js_url)
                try:
                    js_resp = self.session.get(full_url, headers=headers,
                                              timeout=10)
                    # Extract API paths
                    paths = re.findall(
                        r'["\'](/api/[a-zA-Z0-9/_-]+)["\']', js_resp.text)
                    endpoints.update(paths)

                    # Extract fetch/axios URLs
                    fetch_urls = re.findall(
                        r'(?:fetch|axios|get|post|put|delete)\s*\(\s*["\']([^"\']+)["\']',
                        js_resp.text, re.IGNORECASE)
                    for u in fetch_urls:
                        if u.startswith("/") or u.startswith("http"):
                            endpoints.add(u)

                except Exception:
                    continue

                time.sleep(0.3)

        except Exception:
            pass

        self.endpoints.extend(endpoints)
        return sorted(endpoints)

    def discover(self, headers: dict = None) -> dict:
        """Run all discovery checks."""
        headers = headers or {}
        results = {
            "base_url": self.base_url,
            "swagger": self.discover_swagger(headers),
            "graphql": self.discover_graphql(headers),
            "postman": self.discover_postman(headers),
            "debug": self.discover_debug_endpoints(headers),
            "js_endpoints": self.extract_endpoints_from_js(headers),
            "total_findings": len(self.findings),
            "total_endpoints": len(set(self.endpoints)),
        }
        return results

    def save_findings(self, target: str) -> None:
        out_dir = Path(f"findings/{target}/api_discovery")
        out_dir.mkdir(parents=True, exist_ok=True)
        if self.findings:
            out_file = out_dir / f"api_docs_{int(time.time())}.json"
            out_file.write_text(json.dumps(self.findings, indent=2, default=str))
        if self.endpoints:
            ep_file = out_dir / "discovered_endpoints.txt"
            ep_file.write_text("\n".join(sorted(set(self.endpoints))))
