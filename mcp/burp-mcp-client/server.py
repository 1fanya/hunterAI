#!/usr/bin/env python3
"""
Burp Suite MCP Server — MCP stdio protocol for Claude Code integration.

Proxies to Burp Suite's REST API (default: http://127.0.0.1:1337).

Tools:
  - get_proxy_history: Fetch intercepted HTTP requests/responses
  - search_proxy: Search proxy history by URL, method, status code
  - get_sitemap: Get discovered URLs from Burp's target sitemap
  - send_to_repeater: Send a crafted request to Burp Repeater
  - start_active_scan: Launch an active scan on a URL
  - get_scan_status: Check status and findings of a scan
  - get_issue_definitions: List all Burp issue type definitions

Env vars:
  BURP_API_URL  — Burp REST API base URL (default: http://127.0.0.1:1337)
  BURP_API_KEY  — Burp REST API key (if configured)

Prerequisites:
  Burp Suite must be running with REST API enabled:
    java -jar burpsuite_pro.jar --rest-api --rest-api-key=<key>

Usage:
  python3 server.py                    # MCP stdio mode
  python3 server.py history --limit 5  # CLI test
  python3 server.py sitemap            # CLI test
"""

import json
import os
import sys
import urllib.request
import urllib.error

BURP_API_URL = os.environ.get("BURP_API_URL", "http://127.0.0.1:1337")
BURP_API_KEY = os.environ.get("BURP_API_KEY", "")
DEFAULT_TIMEOUT = 10


def _burp_request(path, method="GET", data=None, timeout=DEFAULT_TIMEOUT):
    """Make request to Burp REST API."""
    url = f"{BURP_API_URL}{path}"
    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json",
    }
    if BURP_API_KEY:
        headers["Authorization"] = BURP_API_KEY

    body = json.dumps(data).encode("utf-8") if data else None
    req = urllib.request.Request(url, data=body, headers=headers, method=method)

    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read().decode("utf-8", errors="replace")
            return json.loads(raw) if raw.strip() else {"status": "ok"}
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", errors="replace") if e.fp else ""
        return {"error": f"HTTP {e.code}: {e.reason}", "details": body[:500]}
    except urllib.error.URLError as e:
        return {
            "error": f"Cannot connect to Burp at {BURP_API_URL}",
            "hint": "Make sure Burp Suite is running with --rest-api flag",
            "details": str(e.reason),
        }


# ═══════════════════════════════════════════════════════════════════════════════
#  TOOLS
# ═══════════════════════════════════════════════════════════════════════════════

def get_proxy_history(limit=20, offset=0):
    """Get recent proxy history entries."""
    result = _burp_request(f"/v0.1/proxy/history?limit={limit}&offset={offset}")
    if "error" in result:
        return result

    entries = []
    for item in result if isinstance(result, list) else result.get("data", []):
        entries.append({
            "index": item.get("index", ""),
            "host": item.get("host", ""),
            "port": item.get("port", ""),
            "protocol": item.get("protocol", ""),
            "method": item.get("method", ""),
            "path": item.get("path", ""),
            "status": item.get("status", ""),
            "length": item.get("response_length", ""),
            "mime_type": item.get("mime_type", ""),
        })
    return {"entries": entries, "count": len(entries)}


def search_proxy(url_contains="", method="", status_code=None, limit=20):
    """Search proxy history by URL pattern, method, or status code."""
    result = _burp_request("/v0.1/proxy/history")
    if "error" in result:
        return result

    items = result if isinstance(result, list) else result.get("data", [])
    matches = []

    for item in items:
        full_url = f"{item.get('protocol', 'https')}://{item.get('host', '')}{item.get('path', '')}"

        if url_contains and url_contains.lower() not in full_url.lower():
            continue
        if method and item.get("method", "").upper() != method.upper():
            continue
        if status_code and str(item.get("status", "")) != str(status_code):
            continue

        matches.append({
            "index": item.get("index", ""),
            "url": full_url,
            "method": item.get("method", ""),
            "status": item.get("status", ""),
            "length": item.get("response_length", ""),
            "mime_type": item.get("mime_type", ""),
        })

        if len(matches) >= limit:
            break

    return {"matches": matches, "count": len(matches)}


def get_sitemap(url_prefix="", limit=50):
    """Get Burp's target sitemap."""
    path = "/v0.1/target/sitemap"
    if url_prefix:
        path += f"?urlPrefix={urllib.request.quote(url_prefix, safe='')}"

    result = _burp_request(path)
    if "error" in result:
        return result

    items = result if isinstance(result, list) else result.get("data", [])
    urls = []
    for item in items[:limit]:
        urls.append({
            "url": item.get("url", ""),
            "method": item.get("method", ""),
            "status": item.get("status_code", ""),
            "has_response": item.get("response") is not None,
        })
    return {"urls": urls, "count": len(urls)}


def send_to_repeater(host, port, protocol, request_raw):
    """Send a request to Burp Repeater."""
    data = {
        "host": host,
        "port": int(port),
        "useHttps": protocol.lower() == "https",
        "request": request_raw,
    }
    result = _burp_request("/v0.1/repeater", method="POST", data=data)
    if "error" in result:
        return result
    return {"success": True, "message": f"Request sent to Repeater: {host}"}


def start_active_scan(url):
    """Start an active scan on a URL."""
    data = {"urls": [url]}
    result = _burp_request("/v0.1/scan", method="POST", data=data)
    if "error" in result:
        return result
    task_id = result.get("task_id", result.get("id", "unknown"))
    return {"success": True, "task_id": task_id, "url": url, "message": "Scan started"}


def get_scan_status(task_id="0"):
    """Get scan status and findings."""
    result = _burp_request(f"/v0.1/scan/{task_id}")
    if "error" in result:
        return result

    issues = []
    for issue in result.get("issue_events", result.get("issues", [])):
        detail = issue.get("issue", issue)
        issues.append({
            "name": detail.get("name", ""),
            "severity": detail.get("severity", ""),
            "confidence": detail.get("confidence", ""),
            "path": detail.get("path", ""),
            "description": (detail.get("description") or "")[:300],
        })

    return {
        "status": result.get("scan_status", "unknown"),
        "metrics": result.get("scan_metrics", {}),
        "issues": issues,
        "issue_count": len(issues),
    }


def get_issue_definitions():
    """Get all Burp issue type definitions."""
    result = _burp_request("/v0.1/knowledge_base/issue_definitions")
    if "error" in result:
        return result

    items = result if isinstance(result, list) else result.get("data", [])
    definitions = []
    for item in items[:50]:
        definitions.append({
            "name": item.get("name", ""),
            "type_index": item.get("issue_type_id", ""),
            "severity": item.get("typical_severity", ""),
        })
    return {"definitions": definitions, "count": len(definitions)}


# ═══════════════════════════════════════════════════════════════════════════════
#  MCP STDIO PROTOCOL
# ═══════════════════════════════════════════════════════════════════════════════

TOOLS = [
    {
        "name": "get_proxy_history",
        "description": "Get recent HTTP requests/responses from Burp proxy history.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "limit": {"type": "integer", "description": "Max entries", "default": 20},
                "offset": {"type": "integer", "description": "Start offset", "default": 0},
            },
        },
    },
    {
        "name": "search_proxy",
        "description": "Search Burp proxy history by URL, HTTP method, or status code.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "url_contains": {"type": "string", "description": "URL substring to match"},
                "method": {"type": "string", "description": "HTTP method (GET, POST, etc.)"},
                "status_code": {"type": "integer", "description": "Response status code"},
                "limit": {"type": "integer", "description": "Max results", "default": 20},
            },
        },
    },
    {
        "name": "get_sitemap",
        "description": "Get URLs from Burp's target sitemap.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "url_prefix": {"type": "string", "description": "Filter by URL prefix"},
                "limit": {"type": "integer", "description": "Max results", "default": 50},
            },
        },
    },
    {
        "name": "send_to_repeater",
        "description": "Send a crafted HTTP request to Burp Repeater for manual testing.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "host": {"type": "string", "description": "Target hostname"},
                "port": {"type": "integer", "description": "Port number", "default": 443},
                "protocol": {"type": "string", "description": "http or https", "default": "https"},
                "request_raw": {"type": "string", "description": "Raw HTTP request string"},
            },
            "required": ["host", "request_raw"],
        },
    },
    {
        "name": "start_active_scan",
        "description": "Launch a Burp active scan on a target URL.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "url": {"type": "string", "description": "Full URL to scan"},
            },
            "required": ["url"],
        },
    },
    {
        "name": "get_scan_status",
        "description": "Check status and findings of a Burp active scan.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "task_id": {"type": "string", "description": "Scan task ID", "default": "0"},
            },
        },
    },
    {
        "name": "get_issue_definitions",
        "description": "List all Burp vulnerability issue type definitions.",
        "inputSchema": {"type": "object", "properties": {}},
    },
]

TOOL_DISPATCH = {
    "get_proxy_history": lambda a: get_proxy_history(a.get("limit", 20), a.get("offset", 0)),
    "search_proxy": lambda a: search_proxy(
        a.get("url_contains", ""), a.get("method", ""),
        a.get("status_code"), a.get("limit", 20),
    ),
    "get_sitemap": lambda a: get_sitemap(a.get("url_prefix", ""), a.get("limit", 50)),
    "send_to_repeater": lambda a: send_to_repeater(
        a["host"], a.get("port", 443), a.get("protocol", "https"), a["request_raw"],
    ),
    "start_active_scan": lambda a: start_active_scan(a["url"]),
    "get_scan_status": lambda a: get_scan_status(a.get("task_id", "0")),
    "get_issue_definitions": lambda a: get_issue_definitions(),
}


def handle_mcp_request(request):
    """Handle a single MCP JSON-RPC request."""
    method = request.get("method", "")
    req_id = request.get("id")
    params = request.get("params", {})

    if method == "initialize":
        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "result": {
                "protocolVersion": "2024-11-05",
                "capabilities": {"tools": {"listChanged": False}},
                "serverInfo": {"name": "burp-mcp", "version": "1.0.0"},
            },
        }

    elif method == "notifications/initialized":
        return None

    elif method == "tools/list":
        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "result": {"tools": TOOLS},
        }

    elif method == "tools/call":
        tool_name = params.get("name", "")
        tool_args = params.get("arguments", {})

        if tool_name not in TOOL_DISPATCH:
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {
                    "content": [{"type": "text", "text": f"Unknown tool: {tool_name}"}],
                    "isError": True,
                },
            }

        try:
            result = TOOL_DISPATCH[tool_name](tool_args)
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {
                    "content": [{"type": "text", "text": json.dumps(result, indent=2)}],
                    "isError": False,
                },
            }
        except Exception as e:
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {
                    "content": [{"type": "text", "text": f"Error: {str(e)}"}],
                    "isError": True,
                },
            }

    elif method == "ping":
        return {"jsonrpc": "2.0", "id": req_id, "result": {}}

    else:
        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "error": {"code": -32601, "message": f"Method not found: {method}"},
        }


def run_mcp_stdio():
    """Run MCP server over stdin/stdout."""
    sys.stderr.write(f"[burp-mcp] Server started (Burp API: {BURP_API_URL})\n")
    sys.stderr.flush()

    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue

        try:
            request = json.loads(line)
        except json.JSONDecodeError:
            continue

        response = handle_mcp_request(request)
        if response is not None:
            sys.stdout.write(json.dumps(response) + "\n")
            sys.stdout.flush()


# ─── CLI test mode ───────────────────────────────────────────────────────────

def main_cli():
    """CLI test mode for quick checks."""
    if len(sys.argv) < 2:
        print("Usage:")
        print("  python3 server.py                     # MCP stdio mode")
        print("  python3 server.py history [--limit N]  # Proxy history")
        print("  python3 server.py sitemap [url_prefix] # Target sitemap")
        print("  python3 server.py search <url_part>    # Search proxy")
        print("  python3 server.py scan <url>           # Start active scan")
        print("  python3 server.py status [task_id]     # Scan status")
        sys.exit(1)

    cmd = sys.argv[1]

    if cmd == "history":
        limit = 20
        if "--limit" in sys.argv:
            idx = sys.argv.index("--limit")
            limit = int(sys.argv[idx + 1]) if idx + 1 < len(sys.argv) else 20
        print(json.dumps(get_proxy_history(limit), indent=2))

    elif cmd == "sitemap":
        prefix = sys.argv[2] if len(sys.argv) > 2 else ""
        print(json.dumps(get_sitemap(prefix), indent=2))

    elif cmd == "search":
        url_part = sys.argv[2] if len(sys.argv) > 2 else ""
        print(json.dumps(search_proxy(url_contains=url_part), indent=2))

    elif cmd == "scan":
        url = sys.argv[2] if len(sys.argv) > 2 else ""
        if not url: print("Error: URL required"); sys.exit(1)
        print(json.dumps(start_active_scan(url), indent=2))

    elif cmd == "status":
        tid = sys.argv[2] if len(sys.argv) > 2 else "0"
        print(json.dumps(get_scan_status(tid), indent=2))

    else:
        print(f"Unknown command: {cmd}")
        sys.exit(1)


if __name__ == "__main__":
    if len(sys.argv) == 1:
        run_mcp_stdio()
    else:
        main_cli()
