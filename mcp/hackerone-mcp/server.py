#!/usr/bin/env python3
"""
HackerOne MCP Server — MCP stdio protocol for Claude Code integration.

Provides public + authenticated tools for HackerOne interaction:

Public (no auth):
  - search_disclosed_reports: Search Hacktivity for disclosed reports
  - get_program_stats: Bounty ranges, response times, resolved counts
  - get_program_policy: Safe harbor, scope, excluded vuln classes

Authenticated (H1_API_TOKEN + H1_API_USERNAME):
  - get_my_reports: List your submitted reports + status
  - add_report_comment: Add comment to a report
  - close_report: Self-close a report
  - get_program_scope: Authenticated scope import

Env vars:
  H1_API_TOKEN     — HackerOne API token (Settings > API Tokens)
  H1_API_USERNAME  — Your HackerOne username

Usage:
  # MCP mode (Claude Code uses this)
  python3 server.py

  # CLI test mode
  python3 server.py search "ssrf" --limit 5
  python3 server.py stats "rockstargames"
  python3 server.py policy "rockstargames"
  python3 server.py my-reports
"""

import base64
import json
import os
import ssl
import sys
import urllib.request
import urllib.error
from datetime import datetime, timezone

# ─── SSL context ─────────────────────────────────────────────────────────────
_SSL_CTX = ssl.create_default_context()
try:
    import certifi
    _SSL_CTX = ssl.create_default_context(cafile=certifi.where())
except ImportError:
    _SSL_CTX.check_hostname = False
    _SSL_CTX.verify_mode = ssl.CERT_NONE

H1_GRAPHQL = "https://hackerone.com/graphql"
H1_API_BASE = "https://api.hackerone.com/v1"
DEFAULT_TIMEOUT = 15

# ─── Auth ─────────────────────────────────────────────────────────────────────

def _get_auth_header():
    """Build Basic auth header from env vars."""
    username = os.environ.get("H1_API_USERNAME", "")
    token = os.environ.get("H1_API_TOKEN", "")
    if not username or not token:
        return None
    creds = base64.b64encode(f"{username}:{token}".encode()).decode()
    return f"Basic {creds}"


def _api_request(path, method="GET", data=None, timeout=DEFAULT_TIMEOUT):
    """Make authenticated request to H1 REST API v1."""
    auth = _get_auth_header()
    if not auth:
        return {"error": "Missing H1_API_USERNAME or H1_API_TOKEN env vars"}

    url = f"{H1_API_BASE}{path}"
    headers = {
        "Authorization": auth,
        "Content-Type": "application/json",
        "Accept": "application/json",
        "User-Agent": "hunterAI-mcp/1.0",
    }

    body = json.dumps(data).encode("utf-8") if data else None
    req = urllib.request.Request(url, data=body, headers=headers, method=method)

    try:
        with urllib.request.urlopen(req, timeout=timeout, context=_SSL_CTX) as resp:
            return json.loads(resp.read().decode("utf-8", errors="replace"))
    except urllib.error.HTTPError as e:
        error_body = e.read().decode("utf-8", errors="replace") if e.fp else ""
        return {"error": f"HTTP {e.code}: {e.reason}", "details": error_body[:500]}
    except urllib.error.URLError as e:
        return {"error": f"Network error: {e.reason}"}


def _graphql_request(query, timeout=DEFAULT_TIMEOUT):
    """Execute a GraphQL request against HackerOne's public API."""
    payload = json.dumps({"query": query}).encode("utf-8")
    req = urllib.request.Request(
        H1_GRAPHQL,
        data=payload,
        headers={
            "Content-Type": "application/json",
            "User-Agent": "hunterAI-mcp/1.0",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=_SSL_CTX) as resp:
            body = resp.read().decode("utf-8", errors="replace")
            data = json.loads(body)
            if "errors" in data:
                return {"error": f"GraphQL errors: {data['errors']}"}
            return data
    except urllib.error.HTTPError as e:
        return {"error": f"HTTP {e.code}: {e.reason}"}
    except urllib.error.URLError as e:
        return {"error": f"Network error: {e.reason}"}


# ═══════════════════════════════════════════════════════════════════════════════
#  PUBLIC TOOLS (no auth)
# ═══════════════════════════════════════════════════════════════════════════════

def search_disclosed_reports(keyword="", program="", limit=10):
    """Search HackerOne Hacktivity for disclosed reports."""
    limit = max(1, min(25, limit))

    where_clauses = ['disclosed_at: { _is_null: false }']
    if keyword:
        safe_kw = keyword.replace('"', '\\"')
        where_clauses.append(f'report: {{ title: {{ _icontains: "{safe_kw}" }} }}')
    if program:
        safe_prog = program.replace('"', '\\"')
        where_clauses.append(f'team: {{ handle: {{ _eq: "{safe_prog}" }} }}')

    where = ", ".join(where_clauses)
    query = f"""{{
      hacktivity_items(
        first: {limit},
        order_by: {{ field: popular, direction: DESC }},
        where: {{ {where} }}
      ) {{
        nodes {{
          ... on HacktivityDocument {{
            report {{
              title
              severity_rating
              disclosed_at
              url
              substate
            }}
            team {{
              handle
              name
            }}
          }}
        }}
      }}
    }}"""

    data = _graphql_request(query)
    if "error" in data:
        return data

    nodes = (data.get("data") or {}).get("hacktivity_items", {}).get("nodes", [])
    results = []
    for node in nodes:
        report = node.get("report")
        if not report:
            continue
        team = node.get("team") or {}
        results.append({
            "title": report.get("title", ""),
            "severity": (report.get("severity_rating") or "unknown").upper(),
            "disclosed_at": (report.get("disclosed_at") or "")[:10],
            "url": report.get("url", ""),
            "state": report.get("substate", ""),
            "program": team.get("handle", ""),
            "program_name": team.get("name", ""),
        })
    return results


def get_program_stats(program):
    """Get public statistics for a HackerOne program."""
    safe_prog = program.replace('"', '\\"')
    query = f"""{{
      team(handle: "{safe_prog}") {{
        name handle url offers_bounties default_currency base_bounty
        resolved_report_count average_time_to_bounty_awarded
        average_time_to_first_program_response launched_at state
      }}
    }}"""

    data = _graphql_request(query)
    if "error" in data:
        return data

    team = (data.get("data") or {}).get("team")
    if not team:
        return {"error": f"Program '{program}' not found"}

    return {
        "program": team.get("handle", ""),
        "name": team.get("name", ""),
        "url": team.get("url", ""),
        "offers_bounties": team.get("offers_bounties", False),
        "currency": team.get("default_currency", "USD"),
        "base_bounty": team.get("base_bounty"),
        "resolved_reports": team.get("resolved_report_count"),
        "avg_days_to_bounty": team.get("average_time_to_bounty_awarded"),
        "avg_days_to_first_response": team.get("average_time_to_first_program_response"),
        "launched_at": (team.get("launched_at") or "")[:10],
        "state": team.get("state", ""),
    }


def get_program_policy(program):
    """Get public policy and scope for a HackerOne program."""
    safe_prog = program.replace('"', '\\"')
    query = f"""{{
      team(handle: "{safe_prog}") {{
        name handle policy offers_bounties
        structured_scopes(first: 50, archived: false) {{
          nodes {{
            asset_type asset_identifier eligible_for_bounty
            eligible_for_submission instruction
          }}
        }}
      }}
    }}"""

    data = _graphql_request(query)
    if "error" in data:
        return data

    team = (data.get("data") or {}).get("team")
    if not team:
        return {"error": f"Program '{program}' not found"}

    scopes = []
    for s in (team.get("structured_scopes") or {}).get("nodes", []):
        scopes.append({
            "type": s.get("asset_type", ""),
            "identifier": s.get("asset_identifier", ""),
            "bounty_eligible": s.get("eligible_for_bounty", False),
            "instruction": (s.get("instruction") or "")[:200],
        })

    return {
        "program": team.get("handle", ""),
        "name": team.get("name", ""),
        "offers_bounties": team.get("offers_bounties", False),
        "policy_text": (team.get("policy") or "")[:2000],
        "scopes": scopes,
    }


# ═══════════════════════════════════════════════════════════════════════════════
#  AUTHENTICATED TOOLS (H1_API_TOKEN required)
# ═══════════════════════════════════════════════════════════════════════════════

def get_my_reports(state="new,triaged,needs-more-info", page_size=10):
    """List your submitted reports with status."""
    params = f"?filter[state][]={state}&page[size]={page_size}"
    data = _api_request(f"/hackers/me/reports{params}")
    if "error" in data:
        return data

    reports = []
    for r in data.get("data", []):
        attrs = r.get("attributes", {})
        reports.append({
            "id": r.get("id", ""),
            "title": attrs.get("title", ""),
            "state": attrs.get("state", ""),
            "substate": attrs.get("substate", ""),
            "severity": (attrs.get("severity_rating") or "none"),
            "bounty_awarded": attrs.get("bounty_awarded_at") is not None,
            "created_at": (attrs.get("created_at") or "")[:10],
            "triaged_at": (attrs.get("triaged_at") or "")[:10],
        })
    return {"reports": reports, "count": len(reports)}


def add_report_comment(report_id, message, internal=False):
    """Add a comment to a report."""
    data = {
        "data": {
            "type": "activity-comment",
            "attributes": {
                "message": message,
                "internal": internal,
            }
        }
    }
    result = _api_request(f"/reports/{report_id}/activities", method="POST", data=data)
    if "error" in result:
        return result
    return {"success": True, "report_id": report_id, "message": "Comment added"}


def close_report(report_id, message="Self-closing this report."):
    """Self-close a report with a comment."""
    data = {
        "data": {
            "type": "activity-hacker-requested-mediation",
            "attributes": {
                "message": message,
            }
        }
    }
    result = _api_request(f"/reports/{report_id}/state_change", method="POST", data=data)
    if "error" in result:
        # Try alternative close method
        comment_result = add_report_comment(report_id, message)
        return {
            "partial": True,
            "comment_added": "error" not in comment_result,
            "note": "Comment added but state change may require manual close on H1 UI",
        }
    return {"success": True, "report_id": report_id, "message": "Report closed"}


def get_program_scope_auth(program):
    """Get authenticated program scope (more detail than public)."""
    data = _api_request(f"/hackers/programs/{program}")
    if "error" in data:
        return data

    relationships = (data.get("data") or {}).get("relationships", {})
    scopes_data = relationships.get("structured_scopes", {}).get("data", [])

    scopes = []
    for s in scopes_data:
        attrs = s.get("attributes", {})
        scopes.append({
            "type": attrs.get("asset_type", ""),
            "identifier": attrs.get("asset_identifier", ""),
            "bounty_eligible": attrs.get("eligible_for_bounty", False),
            "max_severity": attrs.get("max_severity", ""),
            "instruction": (attrs.get("instruction") or "")[:300],
        })

    return {"program": program, "scopes": scopes, "count": len(scopes)}


# ═══════════════════════════════════════════════════════════════════════════════
#  MCP STDIO PROTOCOL
# ═══════════════════════════════════════════════════════════════════════════════

TOOLS = [
    {
        "name": "search_disclosed_reports",
        "description": "Search HackerOne Hacktivity for disclosed bug reports. Use to check for duplicates or learn from past findings.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "keyword": {"type": "string", "description": "Search term (e.g. 'ssrf', 'idor', 'xss')"},
                "program": {"type": "string", "description": "H1 program handle (e.g. 'shopify')"},
                "limit": {"type": "integer", "description": "Max results (1-25)", "default": 10},
            },
        },
    },
    {
        "name": "get_program_stats",
        "description": "Get public stats for a H1 program: bounty range, response times, resolved count.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "program": {"type": "string", "description": "H1 program handle"},
            },
            "required": ["program"],
        },
    },
    {
        "name": "get_program_policy",
        "description": "Get program policy, scope (in-scope assets), and rules.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "program": {"type": "string", "description": "H1 program handle"},
            },
            "required": ["program"],
        },
    },
    {
        "name": "get_my_reports",
        "description": "List your submitted H1 reports with status. Requires H1_API_TOKEN.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "state": {"type": "string", "description": "Filter by state: new,triaged,needs-more-info,resolved,not-applicable", "default": "new,triaged,needs-more-info"},
                "page_size": {"type": "integer", "description": "Results per page", "default": 10},
            },
        },
    },
    {
        "name": "add_report_comment",
        "description": "Add a comment to a H1 report. Requires H1_API_TOKEN.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "report_id": {"type": "string", "description": "Report ID number"},
                "message": {"type": "string", "description": "Comment text"},
                "internal": {"type": "boolean", "description": "Internal note (not visible to program)", "default": False},
            },
            "required": ["report_id", "message"],
        },
    },
    {
        "name": "close_report",
        "description": "Self-close a H1 report with a message. Requires H1_API_TOKEN.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "report_id": {"type": "string", "description": "Report ID number"},
                "message": {"type": "string", "description": "Closing message"},
            },
            "required": ["report_id", "message"],
        },
    },
    {
        "name": "get_program_scope_auth",
        "description": "Get detailed authenticated scope for a program. Requires H1_API_TOKEN.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "program": {"type": "string", "description": "H1 program handle"},
            },
            "required": ["program"],
        },
    },
]

TOOL_DISPATCH = {
    "search_disclosed_reports": lambda args: search_disclosed_reports(
        keyword=args.get("keyword", ""),
        program=args.get("program", ""),
        limit=args.get("limit", 10),
    ),
    "get_program_stats": lambda args: get_program_stats(args["program"]),
    "get_program_policy": lambda args: get_program_policy(args["program"]),
    "get_my_reports": lambda args: get_my_reports(
        state=args.get("state", "new,triaged,needs-more-info"),
        page_size=args.get("page_size", 10),
    ),
    "add_report_comment": lambda args: add_report_comment(
        args["report_id"], args["message"], args.get("internal", False),
    ),
    "close_report": lambda args: close_report(
        args["report_id"], args.get("message", "Self-closing this report."),
    ),
    "get_program_scope_auth": lambda args: get_program_scope_auth(args["program"]),
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
                "serverInfo": {
                    "name": "hackerone-mcp",
                    "version": "1.0.0",
                },
            },
        }

    elif method == "notifications/initialized":
        return None  # No response for notifications

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
        # Unknown method — return error
        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "error": {"code": -32601, "message": f"Method not found: {method}"},
        }


def run_mcp_stdio():
    """Run MCP server over stdin/stdout (JSON-RPC)."""
    sys.stderr.write("[hackerone-mcp] Server started (stdio mode)\n")
    sys.stderr.flush()

    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue

        try:
            request = json.loads(line)
        except json.JSONDecodeError:
            sys.stderr.write(f"[hackerone-mcp] Invalid JSON: {line[:100]}\n")
            sys.stderr.flush()
            continue

        response = handle_mcp_request(request)

        if response is not None:
            sys.stdout.write(json.dumps(response) + "\n")
            sys.stdout.flush()


# ─── CLI interface ───────────────────────────────────────────────────────────

def main_cli():
    """CLI test mode."""
    if len(sys.argv) < 2:
        print("Usage:")
        print("  python3 server.py                               # MCP stdio mode")
        print("  python3 server.py search <keyword> [--program X] [--limit N]")
        print("  python3 server.py stats <program>")
        print("  python3 server.py policy <program>")
        print("  python3 server.py my-reports")
        sys.exit(1)

    cmd = sys.argv[1]

    if cmd == "search":
        kw = sys.argv[2] if len(sys.argv) > 2 else ""
        program, limit = "", 10
        i = 3
        while i < len(sys.argv):
            if sys.argv[i] == "--program" and i + 1 < len(sys.argv):
                program = sys.argv[i + 1]; i += 2
            elif sys.argv[i] == "--limit" and i + 1 < len(sys.argv):
                limit = int(sys.argv[i + 1]); i += 2
            else:
                i += 1
        print(json.dumps(search_disclosed_reports(kw, program, limit), indent=2))

    elif cmd == "stats":
        program = sys.argv[2] if len(sys.argv) > 2 else ""
        if not program: print("Error: program handle required"); sys.exit(1)
        print(json.dumps(get_program_stats(program), indent=2))

    elif cmd == "policy":
        program = sys.argv[2] if len(sys.argv) > 2 else ""
        if not program: print("Error: program handle required"); sys.exit(1)
        print(json.dumps(get_program_policy(program), indent=2))

    elif cmd == "my-reports":
        print(json.dumps(get_my_reports(), indent=2))

    else:
        print(f"Unknown command: {cmd}")
        sys.exit(1)


if __name__ == "__main__":
    if len(sys.argv) == 1:
        # No args = MCP stdio mode
        run_mcp_stdio()
    else:
        main_cli()
