#!/usr/bin/env python3
"""
agent.py — LangGraph-style ReAct hunting agent for bug bounty automation.

Architecture
────────────
Primary:  Real LangGraph + langchain-ollama  (pip install langgraph langchain-ollama)
Fallback: Built-in ReAct loop using Ollama native tool calling  (works out of the box)

Both paths expose identical tools and persistent memory — the difference is
that the real LangGraph backend handles interrupts, checkpoints, and parallel
subgraphs correctly.

ReAct loop:
    Observe (state) → Think (LLM) → Act (tool) → Observe (result) → loop
    ↳ LLM picks next tool based on ALL prior findings, not a priority table
    ↳ Working memory is compressed every 5 steps to stay within context window
    ↳ Full finding history persists to JSON session — survives crashes/restarts

Memory layers
─────────────
  working_memory  : LLM-maintained running notes (updated after each step)
  findings_log    : [{tool, severity, summary, timestamp}, ...]
  observation_buf : last 5 raw tool outputs (sliding window, avoids bloat)
  session_file    : everything above persisted to disk (JSON)

Usage
─────
  python3 agent.py --target example.com
  python3 agent.py --target example.com --cookie "JSESSIONID=abc" --time 4
  python3 agent.py --target example.com --scope-lock --no-brain
  python3 agent.py --target example.com --langgraph          # force LangGraph
  python3 agent.py --target example.com --resume SESSION_ID

From hunt.py:
  hunt.py --target x --agent              # drops into agent mode
  hunt.py --target x --agent --langgraph  # with real LangGraph
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
import traceback
from datetime import datetime
from pathlib import Path
from typing import Any

# ── LangGraph optional import ──────────────────────────────────────────────────
try:
    from langgraph.graph import StateGraph, END
    from langgraph.graph.message import add_messages
    from langgraph.prebuilt import ToolNode, tools_condition
    from langchain_core.messages import HumanMessage, SystemMessage, AIMessage, ToolMessage
    from langchain_core.tools import tool as lc_tool
    try:
        from langchain_ollama import ChatOllama
        _LANGGRAPH_OK = True
    except ImportError:
        from langchain_community.chat_models import ChatOllama
        _LANGGRAPH_OK = True
except ImportError:
    _LANGGRAPH_OK = False
    StateGraph = END = None
    add_messages = None

# ── Ollama native tool calling (fallback / always available) ───────────────────
try:
    import ollama as _ollama_lib
    _OLLAMA_OK = True
except ImportError:
    _ollama_lib = None
    _OLLAMA_OK = False

# ── hunt.py lazy imports (avoids running main()) ───────────────────────────────
_hunt = None
def _h():
    """Lazy-load hunt module once."""
    global _hunt
    if _hunt is None:
        import importlib.util, sys as _sys
        _here = os.path.dirname(os.path.abspath(__file__))
        spec = importlib.util.spec_from_file_location("hunt", os.path.join(_here, "hunt.py"))
        _hunt = importlib.util.module_from_spec(spec)
        _sys.modules.setdefault("hunt", _hunt)
        spec.loader.exec_module(_hunt)
    return _hunt

# ── brain.py import ───────────────────────────────────────────────────────────
try:
    _here = os.path.dirname(os.path.abspath(__file__))
    sys.path.insert(0, _here)
    sys.path.insert(0, os.path.join(_here, "tools"))  # for new tool imports
    from brain import Brain, BRAIN_SYSTEM, MODEL_PRIORITY, OLLAMA_HOST, _pick_model
    _BRAIN_OK = True
except Exception as _brain_err:
    _BRAIN_OK = False
    BRAIN_SYSTEM = ""
    MODEL_PRIORITY = ["qwen3:8b"]
    OLLAMA_HOST = "http://localhost:11434"

# ── Colours ───────────────────────────────────────────────────────────────────
GREEN   = "\033[0;32m"
CYAN    = "\033[0;36m"
YELLOW  = "\033[1;33m"
RED     = "\033[0;31m"
MAGENTA = "\033[0;35m"
BOLD    = "\033[1m"
DIM     = "\033[2m"
NC      = "\033[0m"

MAX_OBS_CHARS    = 3000    # truncate tool output kept in observation buffer
MAX_CTX_CHARS    = 18000   # max chars sent to LLM per step
MAX_FINDINGS_LOG = 200     # cap stored findings
MEMORY_REFRESH_N = 5       # compress working_memory every N steps


# ──────────────────────────────────────────────────────────────────────────────
#  Tool definitions  (JSON Schema — compatible with Ollama native tool calling)
# ──────────────────────────────────────────────────────────────────────────────

TOOLS: list[dict] = [
    {
        "type": "function",
        "function": {
            "name": "run_recon",
            "description": (
                "Run full subdomain enumeration + live host discovery on the target domain. "
                "This MUST be the first step if recon data does not exist. "
                "Returns: number of live hosts found, key tech stacks detected."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "scope_lock": {
                        "type": "boolean",
                        "description": "If true, skip subdomain enum and only probe the exact target given.",
                        "default": False,
                    },
                    "max_urls": {
                        "type": "integer",
                        "description": "Max URLs to collect (default 100, use 200+ for thorough recon).",
                        "default": 100,
                    },
                },
                "required": [],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "run_vuln_scan",
            "description": (
                "Run the core vulnerability scanner (nuclei templates + custom checks). "
                "Tests for CVEs, misconfigs, exposed panels, default creds, takeover candidates. "
                "Returns: finding count by severity."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "quick": {
                        "type": "boolean",
                        "description": "If true, run fast subset of templates only.",
                        "default": False,
                    },
                    "full": {
                        "type": "boolean",
                        "description": "If true, run all templates including slow ones.",
                        "default": False,
                    },
                },
                "required": [],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "run_js_analysis",
            "description": (
                "Download and analyse all JavaScript files found during recon. "
                "Extracts: API keys, secrets, hardcoded tokens, internal endpoints, "
                "GraphQL schemas, and auth-bypass hints. Use when JS files were discovered."
            ),
            "parameters": {"type": "object", "properties": {}, "required": []},
        },
    },
    {
        "type": "function",
        "function": {
            "name": "run_secret_hunt",
            "description": (
                "Scan for leaked secrets: TruffleHog on JS/git repos, GitHound on GitHub, "
                "hardcoded AWS/GCP/Azure keys, API tokens, private keys. "
                "Always worth running — secrets bypass all other controls."
            ),
            "parameters": {"type": "object", "properties": {}, "required": []},
        },
    },
    {
        "type": "function",
        "function": {
            "name": "run_param_discovery",
            "description": (
                "Brute-force GET URL parameters using arjun + paramspider on all live hosts. "
                "Use when parameterized URLs are sparse or the site returns data conditionally. "
                "Returns: new parameterized URLs added to the attack surface."
            ),
            "parameters": {"type": "object", "properties": {}, "required": []},
        },
    },
    {
        "type": "function",
        "function": {
            "name": "run_post_param_discovery",
            "description": (
                "Discover POST form endpoints and their parameter names using lightpanda "
                "(JS-rendered HTML) + arjun POST brute-force. "
                "Mandatory for JSP/Java/Spring apps, ASP.NET WebForms, any app with login forms. "
                "Then runs sqlmap on discovered POST endpoints automatically. "
                "Pass cookies if the forms are behind authentication."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "cookies": {
                        "type": "string",
                        "description": "Session cookie string e.g. 'JSESSIONID=abc; token=xyz'",
                        "default": "",
                    },
                },
                "required": [],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "run_api_fuzz",
            "description": (
                "Fuzz API endpoints for IDOR, auth bypass, privilege escalation, "
                "and unauthenticated access. Tests REST + GraphQL + gRPC. "
                "Use when API endpoints or numeric IDs were found in recon."
            ),
            "parameters": {"type": "object", "properties": {}, "required": []},
        },
    },
    {
        "type": "function",
        "function": {
            "name": "run_cors_check",
            "description": (
                "Test all live hosts for CORS misconfigurations: null origin, "
                "wildcard with credentials, trusted subdomain bypass. "
                "High-priority when authenticated API endpoints are present."
            ),
            "parameters": {"type": "object", "properties": {}, "required": []},
        },
    },
    {
        "type": "function",
        "function": {
            "name": "run_cms_exploit",
            "description": (
                "Run CMS-specific exploit checks: Drupalgeddon (CVE-2014-3704, CVE-2018-7600), "
                "WordPress plugin vulns + user enum, Joomla RCE, Magento SQLi. "
                "Use immediately when a CMS is detected — especially Drupal < 8 or WordPress."
            ),
            "parameters": {"type": "object", "properties": {}, "required": []},
        },
    },
    {
        "type": "function",
        "function": {
            "name": "run_rce_scan",
            "description": (
                "Scan for Remote Code Execution vectors: Log4Shell (JNDI), Tomcat PUT upload, "
                "JBoss admin consoles, SSTI (Jinja2/Twig/Freemarker), shellshock, "
                "interactsh OOB callbacks. Use when Java/Tomcat/JBoss/Struts is detected."
            ),
            "parameters": {"type": "object", "properties": {}, "required": []},
        },
    },
    {
        "type": "function",
        "function": {
            "name": "run_sqlmap_targeted",
            "description": (
                "Run sqlmap against parameterized GET URLs found in recon. "
                "Tests error-based, boolean-blind, time-blind, UNION injection. "
                "Use when parameterized URLs exist OR nuclei flagged SQL-related findings."
            ),
            "parameters": {"type": "object", "properties": {}, "required": []},
        },
    },
    {
        "type": "function",
        "function": {
            "name": "run_sqlmap_on_file",
            "description": (
                "Run sqlmap against a specific raw HTTP request file (Burp-style). "
                "Use when you know a specific endpoint with POST params that needs SQLi testing. "
                "Provide the full path to the saved request file."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "request_file": {
                        "type": "string",
                        "description": "Absolute path to raw HTTP request file.",
                    },
                    "level": {
                        "type": "integer",
                        "description": "sqlmap level 1-5 (default 5).",
                        "default": 5,
                    },
                    "risk": {
                        "type": "integer",
                        "description": "sqlmap risk 1-3 (default 3).",
                        "default": 3,
                    },
                },
                "required": ["request_file"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "run_jwt_audit",
            "description": (
                "Audit JWT tokens found in recon artifacts: algorithm confusion (alg=none, "
                "RS256→HS256), weak HMAC secret cracking, forged claims. "
                "Use when JWT tokens appear in URLs, cookies, or response headers."
            ),
            "parameters": {"type": "object", "properties": {}, "required": []},
        },
    },
    {
        "type": "function",
        "function": {
            "name": "run_scope_check",
            "description": (
                "Check if a URL or domain is in scope before testing it. "
                "MUST be called before any request to a new domain. "
                "Prevents wasting tokens and accidental out-of-scope testing. "
                "Also filters third-party domains (CDNs, analytics, SaaS)."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "url": {
                        "type": "string",
                        "description": "URL or domain to check against scope.",
                    },
                },
                "required": ["url"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "run_waf_detect",
            "description": (
                "Detect WAF/CDN on the target (Cloudflare, Akamai, AWS WAF, Imperva, etc.) "
                "and get WAF-specific bypass payloads. Run BEFORE active testing — if WAF is "
                "detected, all subsequent payloads should use the bypass variants."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "test_bypass": {
                        "type": "boolean",
                        "description": "If true, also test which bypass payloads pass the WAF.",
                        "default": False,
                    },
                },
                "required": [],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "run_response_diff",
            "description": (
                "Compare HTTP responses between attacker and victim accounts on the same "
                "endpoint. Detects field-level IDOR where attacker sees victim's data. "
                "Tests JSON key/value diff, PII detection (emails, SSN, cards), and "
                "confidence scoring. CRITICAL for finding high-paying IDOR bugs."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "url": {
                        "type": "string",
                        "description": "URL endpoint to test for IDOR.",
                    },
                    "method": {
                        "type": "string",
                        "description": "HTTP method (GET, POST, PUT).",
                        "default": "GET",
                    },
                },
                "required": ["url"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "run_ws_test",
            "description": (
                "Test WebSocket endpoints for vulnerabilities: CSWSH (Cross-Site WebSocket "
                "Hijacking), auth bypass, IDOR in messages, injection in payloads. "
                "WS endpoints bypass WAFs and often have no auth — goldmine for bugs. "
                "Can also discover WS endpoints from JS bundles."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "ws_url": {
                        "type": "string",
                        "description": "WebSocket URL (wss://...) to test. If empty, discovers endpoints.",
                        "default": "",
                    },
                    "victim_id": {
                        "type": "string",
                        "description": "Victim user ID for IDOR testing via WS messages.",
                        "default": "",
                    },
                },
                "required": [],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "run_param_mine",
            "description": (
                "Discover hidden parameters on endpoints using response diffing. "
                "Finds debug modes (?debug=1), admin access (?admin=true), "
                "SSRF entries (?url=), IDOR vectors (?user_id=). "
                "Uses SecLists parameter wordlists for comprehensive coverage."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "url": {
                        "type": "string",
                        "description": "Target endpoint URL to mine for hidden params.",
                    },
                    "method": {
                        "type": "string",
                        "description": "HTTP method (GET or POST).",
                        "default": "GET",
                    },
                },
                "required": ["url"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "run_wordlist_build",
            "description": (
                "Generate target-specific wordlists from recon data: JS bundle paths, "
                "URL path segments, subdomain prefixes, framework-specific paths. "
                "Also installs SecLists subsets if not present. "
                "Run AFTER recon for much better fuzzing results."
            ),
            "parameters": {"type": "object", "properties": {}, "required": []},
        },
    },
    {
        "type": "function",
        "function": {
            "name": "run_nuclei_gen",
            "description": (
                "Auto-generate custom nuclei templates based on detected tech stack "
                "and discovered API endpoints. Creates IDOR probes, framework-specific "
                "checks (Spring Actuator, Laravel Debug, GraphQL introspection), and "
                "config exposure templates. Run AFTER tech profiling."
            ),
            "parameters": {"type": "object", "properties": {}, "required": []},
        },
    },
    {
        "type": "function",
        "function": {
            "name": "run_learn_hacktivity",
            "description": (
                "Self-learning: read HackerOne Hacktivity for the target program, "
                "extract attack patterns and techniques from disclosed reports, "
                "classify by vuln class, and save as learned skills. "
                "Use BEFORE hunting to learn what worked on this program before."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "program": {
                        "type": "string",
                        "description": "HackerOne program handle to learn from.",
                        "default": "",
                    },
                    "count": {
                        "type": "integer",
                        "description": "Number of reports to analyze.",
                        "default": 25,
                    },
                },
                "required": [],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "read_recon_summary",
            "description": (
                "Read and summarize current recon data: live hosts, tech stack, "
                "discovered paths, parameterized URLs, CMS detections. "
                "Use to refresh your understanding before deciding next action."
            ),
            "parameters": {"type": "object", "properties": {}, "required": []},
        },
    },
    {
        "type": "function",
        "function": {
            "name": "read_findings_summary",
            "description": (
                "Read and summarize all vulnerability findings discovered so far. "
                "Returns severity breakdown, top findings, and suggested exploit chains. "
                "Use before deciding to run additional tools or write the final report."
            ),
            "parameters": {"type": "object", "properties": {}, "required": []},
        },
    },
    {
        "type": "function",
        "function": {
            "name": "update_working_memory",
            "description": (
                "Update your working notes about this target. Call this after making "
                "a significant discovery or after each tool run to keep your notes current. "
                "These notes persist across all steps and are always visible to you."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "notes": {
                        "type": "string",
                        "description": "Your updated notes about the target, findings, and next priorities.",
                    }
                },
                "required": ["notes"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "finish",
            "description": (
                "Signal that the hunt is complete. Call this when: all high-priority tools "
                "have run, time budget is close to exhausted, or no further tools would "
                "add new findings. Provide a brief verdict."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "verdict": {
                        "type": "string",
                        "description": "Brief summary: what was found, what's worth reporting.",
                    }
                },
                "required": ["verdict"],
            },
        },
    },
    # ── Advanced hunting tools (Phase 2 upgrade) ──────────────────────────
    {
        "type": "function",
        "function": {
            "name": "run_race_test",
            "description": (
                "Test for race conditions using parallel HTTP requests. "
                "Detects: limit-overrun (coupon/promo reuse), double-spend (transfer money 2x), "
                "TOCTOU. Use on any financial/state-changing endpoint. "
                "Sends 20 parallel requests and compares results."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "url": {"type": "string", "description": "Target endpoint URL"},
                    "method": {"type": "string", "description": "HTTP method (default: POST)", "default": "POST"},
                    "data": {"type": "string", "description": "POST body (JSON string)", "default": ""},
                },
                "required": ["url"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "run_ssrf_test",
            "description": (
                "Test for SSRF with 50+ bypass techniques: decimal/hex/octal IP, "
                "DNS rebinding, URL parsing confusion, protocol smuggling, "
                "and cloud metadata chain (AWS/GCP/Azure). "
                "Use on any endpoint with URL/redirect/callback parameters."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "url": {"type": "string", "description": "Target URL with SSRF-able parameter"},
                    "param": {"type": "string", "description": "Parameter name to inject into"},
                    "callback": {"type": "string", "description": "OOB callback URL (interactsh)", "default": ""},
                },
                "required": ["url", "param"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "run_api_security",
            "description": (
                "OWASP API Top 10 tester: BOLA (systematic ID swapping), "
                "BFLA (admin endpoints with user tokens), mass assignment "
                "(inject role=admin, is_admin=true), and excessive data exposure (PII leak diff). "
                "Use on any REST API. Highest-ROI for API-heavy targets."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "test": {
                        "type": "string",
                        "description": "Test type: bola, bfla, mass_assign, or all",
                        "default": "all",
                    },
                    "victim_id": {"type": "string", "description": "Victim user/resource ID for BOLA test", "default": ""},
                },
                "required": [],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "run_cache_poison",
            "description": (
                "Web cache poisoning + deception tester. Tests unkeyed header injection "
                "(X-Forwarded-Host, X-Original-URL), web cache deception (trick CDN into caching "
                "authenticated pages), and path confusion. Works against Cloudflare/Akamai/Fastly/Varnish. "
                "Pays $10K+. Use on any target behind a CDN."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "url": {"type": "string", "description": "Target URL to test for cache poisoning"},
                },
                "required": ["url"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "run_proto_pollution",
            "description": (
                "Prototype pollution scanner: tests __proto__ and constructor.prototype "
                "injection via query params (client-side) and JSON body (server-side). "
                "Detects known RCE gadgets for Pug, EJS, Handlebars, Lodash. "
                "Use on Node.js/Express targets with JSON merge operations."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "url": {"type": "string", "description": "Target endpoint URL"},
                    "method": {"type": "string", "description": "HTTP method (default: POST)", "default": "POST"},
                },
                "required": ["url"],
            },
        },
    },
    # ── Elite tools (Phase 3 upgrade) ─────────────────────────────────────
    {
        "type": "function",
        "function": {
            "name": "run_chain_escalate",
            "description": (
                "Auto-escalation engine: when a finding is discovered, automatically "
                "attempts to chain it to higher severity. IDOR read → write, "
                "SSRF → cloud metadata, XSS → ATO, redirect → OAuth theft. "
                "This is what turns $500 reports into $50K. Run AFTER any finding."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "finding_json": {"type": "string", "description": "JSON string of the finding to escalate"},
                },
                "required": ["finding_json"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "run_generate_poc",
            "description": (
                "Generate reproducible PoC from a finding: creates curl command, "
                "Python exploit script, and HackerOne report template. "
                "Run AFTER confirming a vulnerability. Makes reports triageable instantly."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "finding_json": {"type": "string", "description": "JSON string of the confirmed finding"},
                },
                "required": ["finding_json"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "run_h2_smuggle",
            "description": (
                "HTTP/2 request smuggling tester: CL.TE, TE.CL, TE obfuscation, "
                "and CRLF header injection. Very few hunters test this — $10K-$75K payouts. "
                "Use on any target behind a reverse proxy (Cloudflare, Akamai, nginx, ALB)."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "url": {"type": "string", "description": "Target URL"},
                },
                "required": ["url"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "run_graphql_deep",
            "description": (
                "Deep GraphQL security tester: discovers endpoint, tests introspection (auth/unauth), "
                "batch IDOR via aliasing (50 users in 1 request), nested query DoS, "
                "field-level auth gaps, and dangerous mutation access. "
                "Use when /graphql or GraphQL responses detected."
            ),
            "parameters": {
                "type": "object",
                "properties": {},
                "required": [],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "run_monitor",
            "description": (
                "Check for attack surface changes since last scan: new subdomains, "
                "new/changed endpoints, new certificates, tech stack changes. "
                "New features = highest priority targets. Run at start of hunt."
            ),
            "parameters": {
                "type": "object",
                "properties": {},
                "required": [],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "run_git_recon",
            "description": (
                "GitHub/GitLab secret hunting: scans org repos for leaked AWS keys, "
                "API tokens, database URLs, private keys in source code + commit history. "
                "14 regex patterns covering all major secret types. Use when org name known."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "org": {"type": "string", "description": "GitHub organization name"},
                },
                "required": ["org"],
            },
        },
    },
    # ── Production tools ──────────────────────────────────────────────────
    {
        "type": "function",
        "function": {
            "name": "run_generate_report",
            "description": (
                "Generate professional H1-quality report from all findings. "
                "Collects, deduplicates, sorts by severity, and outputs "
                "submission-ready markdown + individual H1 submissions. "
                "Run at the END of every hunt before finish."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "min_severity": {
                        "type": "string",
                        "description": "Minimum severity to include: CRITICAL, HIGH, MEDIUM, LOW",
                        "default": "MEDIUM",
                    },
                },
                "required": [],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "run_auth_login",
            "description": (
                "Auto-authenticate with the target: detect login form, "
                "submit credentials, extract session tokens/JWT. "
                "Tokens are saved and used by all subsequent tools. "
                "Run BEFORE any authenticated testing. Requires HUNT_USERNAME and HUNT_PASSWORD env vars."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "login_url": {"type": "string", "description": "Login page URL (auto-detected if empty)", "default": ""},
                },
                "required": [],
            },
        },
    },
    # ── Intelligence layer tools ─────────────────────────────────────
    {
        "type": "function",
        "function": {
            "name": "run_subdomain_takeover",
            "description": (
                "Scan for subdomain takeover: dangling CNAMEs pointing to unclaimed "
                "services (S3, Heroku, GitHub Pages, Azure, Netlify, etc). "
                "15 service fingerprints. Easy $1K-$10K wins. Run after recon."
            ),
            "parameters": {
                "type": "object",
                "properties": {},
                "required": [],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "run_jwt_analysis",
            "description": (
                "Deep JWT security analysis: alg=none confusion (CVE-2015-9235), "
                "brute force HMAC secrets (30+ common passwords), claim tampering "
                "(admin escalation, user ID swap), and expired token reuse. "
                "Use when JWT detected in auth flow."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "token": {"type": "string", "description": "JWT token to analyze"},
                    "verify_url": {"type": "string", "description": "URL to test forged tokens against", "default": ""},
                },
                "required": ["token"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "run_api_discovery",
            "description": (
                "Find API documentation: probes 50+ paths for Swagger/OpenAPI, "
                "GraphQL, Postman collections, debug endpoints (actuator, pprof), "
                "and extracts API paths from JavaScript bundles. "
                "Finding API docs = instant map of every endpoint."
            ),
            "parameters": {
                "type": "object",
                "properties": {},
                "required": [],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "run_blind_xss",
            "description": (
                "Deploy blind XSS payloads: discovers injection points (forms, "
                "params, support/contact/profile fields), injects callback-based "
                "payloads that fire when admin views content. "
                "Requires INTERACTSH_URL env var for callbacks."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "url": {"type": "string", "description": "Target page URL"},
                },
                "required": ["url"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "run_2fa_bypass",
            "description": (
                "Test 2FA/MFA bypass: direct page access (skip 2FA), "
                "response manipulation analysis, OTP rate limiting test "
                "(brutable if no limit), code reuse, weak backup codes. "
                "Use when target has 2FA/MFA."
            ),
            "parameters": {
                "type": "object",
                "properties": {},
                "required": [],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "run_hunt_intel",
            "description": (
                "Cross-hunt intelligence: get strategy recommendations based on "
                "ALL previous hunts. Shows which tools found vulns vs wasted time, "
                "tech stack correlations, and target history. Run at START of hunt."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "tech_stack": {"type": "string", "description": "Comma-separated tech stack (e.g. 'nginx,react,node')", "default": ""},
                },
                "required": [],
            },
        },
    },
    # ── Advanced attack tools ─────────────────────────────────────────────
    {
        "type": "function",
        "function": {
            "name": "run_ssti_scan",
            "description": (
                "Server-Side Template Injection: polyglot detection for 6 engines "
                "(Jinja2, Twig, Freemarker, Velocity, ERB, Mako), "
                "auto-escalates from detection to RCE. Use on pages with user input reflected in response."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "url": {"type": "string", "description": "URL with parameters to test"},
                },
                "required": ["url"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "run_host_header_attack",
            "description": (
                "Host header injection: password reset poisoning (steal reset links), "
                "cache poisoning via X-Forwarded-Host, SSRF via Host. "
                "Test on targets with password reset, caching layers, or reverse proxies."
            ),
            "parameters": {
                "type": "object",
                "properties": {},
                "required": [],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "run_oauth_test",
            "description": (
                "OAuth/OIDC security: redirect_uri manipulation (9 bypass techniques), "
                "missing state parameter (CSRF), scope escalation. "
                "Use when target has OAuth login (Google, GitHub, Facebook etc)."
            ),
            "parameters": {
                "type": "object",
                "properties": {},
                "required": [],
            },
        },
    },
    # ── Final expansion tools ────────────────────────────────────────
    {
        "type": "function",
        "function": {
            "name": "run_xxe_scan",
            "description": (
                "XML External Entity injection: 8 payload types (classic file read, "
                "OOB via interactsh, parameter entity, XInclude, SSRF to cloud metadata). "
                "Also tests SVG/XML file upload XXE. Use on endpoints accepting XML/SOAP."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "url": {"type": "string", "description": "Endpoint to test"},
                    "method": {"type": "string", "description": "HTTP method", "default": "POST"},
                },
                "required": ["url"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "run_open_redirect",
            "description": (
                "Open redirect scanner: 30 bypass payloads, 25 parameter names. "
                "Auto-chains to OAuth token theft. Alone = Low, chained = Critical ATO."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "url": {"type": "string", "description": "URL to test (or base URL for domain scan)"},
                },
                "required": ["url"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "run_file_upload_test",
            "description": (
                "File upload bypass: 20+ extension bypasses (double ext, null byte, case), "
                "content-type manipulation, GIF/PNG+PHP polyglots, path traversal in filename. "
                "Use on any file upload endpoint."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "url": {"type": "string", "description": "Upload endpoint URL"},
                    "field": {"type": "string", "description": "Form field name", "default": "file"},
                },
                "required": ["url"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "run_path_traversal",
            "description": (
                "Path traversal / LFI: 20 WAF bypass encodings (double encode, UTF-8 overlong, "
                "unicode, null byte, Tomcat semicolon). Tests /etc/passwd and win.ini. "
                "Use on endpoints with file/path/template parameters."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "url": {"type": "string", "description": "URL with file parameter to test"},
                },
                "required": ["url"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "run_business_logic_test",
            "description": (
                "Business logic: price manipulation (negative/zero/overflow), quantity abuse, "
                "coupon stacking/reuse/negative discount, checkout workflow bypass. "
                "Auto-discovers cart/payment/coupon endpoints."
            ),
            "parameters": {
                "type": "object",
                "properties": {},
                "required": [],
            },
        },
    },
]

TOOL_NAMES = {t["function"]["name"] for t in TOOLS}


# ──────────────────────────────────────────────────────────────────────────────
#  Memory
# ──────────────────────────────────────────────────────────────────────────────

class HuntMemory:
    """
    Three-layer memory:
      1. working_memory   — LLM's rolling notes (updated by update_working_memory tool)
      2. findings_log     — structured list of all discoveries [{tool, severity, text, ts}]
      3. observation_buf  — last N raw tool outputs, used to build LLM context
    All layers are persisted to a JSON session file.
    """

    def __init__(self, session_file: str):
        self.session_file    = session_file
        self.working_memory  = ""
        self.findings_log:   list[dict] = []
        self.observation_buf: list[dict] = []   # {tool, ts, text}
        self.completed_steps: list[str]  = []
        self.step_count      = 0
        self._load()

    def _load(self) -> None:
        if os.path.isfile(self.session_file):
            try:
                data = json.loads(Path(self.session_file).read_text())
                self.working_memory   = data.get("working_memory", "")
                self.findings_log     = data.get("findings_log", [])
                self.observation_buf  = data.get("observation_buf", [])[-10:]
                self.completed_steps  = data.get("completed_steps", [])
                self.step_count       = data.get("step_count", 0)
            except Exception:
                pass

    def save(self) -> None:
        Path(self.session_file).parent.mkdir(parents=True, exist_ok=True)
        data = {
            "working_memory":  self.working_memory,
            "findings_log":    self.findings_log[-MAX_FINDINGS_LOG:],
            "observation_buf": self.observation_buf[-10:],
            "completed_steps": self.completed_steps,
            "step_count":      self.step_count,
            "saved_at":        datetime.now().isoformat(),
        }
        Path(self.session_file).write_text(json.dumps(data, indent=2))

    def add_observation(self, tool: str, text: str) -> None:
        """Record a tool output to the sliding observation window."""
        entry = {
            "tool": tool,
            "ts":   datetime.now().isoformat(),
            "text": text[:MAX_OBS_CHARS],
        }
        self.observation_buf.append(entry)
        if len(self.observation_buf) > 15:
            self.observation_buf = self.observation_buf[-10:]

    def add_finding(self, tool: str, severity: str, text: str) -> None:
        self.findings_log.append({
            "tool":     tool,
            "severity": severity,
            "text":     text[:500],
            "ts":       datetime.now().isoformat(),
        })

    def findings_summary(self) -> str:
        """Compact summary of all findings for LLM context."""
        if not self.findings_log:
            return "No findings yet."
        by_sev: dict[str, list[str]] = {}
        for f in self.findings_log[-50:]:
            by_sev.setdefault(f["severity"].upper(), []).append(f"{f['tool']}: {f['text'][:120]}")
        lines = []
        for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
            if sev in by_sev:
                lines.append(f"[{sev}] ({len(by_sev[sev])} items)")
                lines.extend(f"  • {x}" for x in by_sev[sev][:5])
        return "\n".join(lines) or "No classified findings."

    def recent_observations(self, n: int = 3) -> str:
        """Last n tool outputs formatted for LLM context."""
        recents = self.observation_buf[-n:]
        if not recents:
            return "No tool outputs yet."
        parts = []
        for obs in recents:
            parts.append(f"[{obs['tool']}]\n{obs['text']}")
        return "\n\n".join(parts)


# ──────────────────────────────────────────────────────────────────────────────
#  Tool dispatcher  (maps tool names → hunt.py functions)
# ──────────────────────────────────────────────────────────────────────────────

class ToolDispatcher:
    """Execute tool calls and return plain-text observations."""

    def __init__(self, domain: str, memory: HuntMemory,
                 scope_lock: bool = False, max_urls: int = 100,
                 default_cookies: str = ""):
        self.domain          = domain
        self.memory          = memory
        self.scope_lock      = scope_lock
        self.max_urls        = max_urls
        self.default_cookies = default_cookies

    def _auth_headers(self) -> dict:
        """Build authentication headers from available sources."""
        headers = {}
        if self.default_cookies:
            headers["Cookie"] = self.default_cookies
        auth_token = os.environ.get("HUNT_AUTH_TOKEN", "")
        if auth_token:
            headers["Authorization"] = f"Bearer {auth_token}"
        return headers

    def dispatch(self, name: str, args: dict) -> str:
        """Execute named tool and return text observation."""
        h = _h()
        domain = self.domain
        t0 = time.time()

        try:
            if name == "run_recon":
                ok = h.run_recon(
                    domain,
                    scope_lock=args.get("scope_lock", self.scope_lock),
                    max_urls=int(args.get("max_urls", self.max_urls)),
                )
                obs = self._summarize_recon(domain, ok)

            elif name == "run_vuln_scan":
                ok = h.run_vuln_scan(
                    domain,
                    quick=bool(args.get("quick", False)),
                    full=bool(args.get("full", False)),
                )
                obs = self._summarize_findings(domain, "scan", ok)

            elif name == "run_js_analysis":
                ok = h.run_js_analysis(domain)
                obs = self._summarize_findings(domain, "js", ok)

            elif name == "run_secret_hunt":
                ok = h.run_secret_hunt(domain)
                obs = self._summarize_findings(domain, "secrets", ok)

            elif name == "run_param_discovery":
                ok = h.run_param_discovery(domain)
                obs = self._summarize_params(domain, ok)

            elif name == "run_post_param_discovery":
                cookies = args.get("cookies", self.default_cookies)
                ok = h.run_post_param_discovery(domain, cookies=cookies)
                obs = self._summarize_post_params(domain, ok)

            elif name == "run_api_fuzz":
                ok = h.run_api_fuzz(domain)
                obs = self._summarize_findings(domain, "api", ok)

            elif name == "run_cors_check":
                ok = h.run_cors_check(domain)
                obs = self._summarize_findings(domain, "cors", ok)

            elif name == "run_cms_exploit":
                ok = h.run_cms_exploit(domain)
                obs = self._summarize_findings(domain, "cms", ok)

            elif name == "run_rce_scan":
                ok = h.run_rce_scan(domain)
                obs = self._summarize_findings(domain, "rce", ok)

            elif name == "run_sqlmap_targeted":
                ok = h.run_sqlmap_targeted(domain)
                obs = self._summarize_findings(domain, "sqlmap", ok)

            elif name == "run_sqlmap_on_file":
                req_file = args.get("request_file", "")
                if not req_file or not os.path.isfile(req_file):
                    return f"ERROR: request_file not found: {req_file}"
                ok = h.run_sqlmap_request_file(
                    req_file, domain=domain,
                    level=int(args.get("level", 5)),
                    risk=int(args.get("risk", 3)),
                )
                obs = f"sqlmap (request-file) completed. Injectable: {ok}"

            elif name == "run_jwt_audit":
                ok = h.run_jwt_audit(domain)
                obs = self._summarize_findings(domain, "jwt", ok)

            # ── New tool dispatchers ────────────────────────────────────
            elif name == "run_scope_check":
                from scope_guard import ScopeGuard
                guard = ScopeGuard(domain)
                url = args.get("url", "")
                in_scope = guard.is_in_scope(url)
                obs = f"Scope check: {url} → {'IN SCOPE ✅' if in_scope else 'OUT OF SCOPE ❌ — SKIP THIS'}"

            elif name == "run_waf_detect":
                from waf_detector import WAFDetector
                detector = WAFDetector()
                result = detector.detect(f"https://{domain}")
                waf_name = result.get("waf", "none")
                obs = f"WAF detection: {waf_name} (confidence: {result.get('confidence_scores', {}).get(waf_name, 0)})\n"
                if result.get("waf_detected") and args.get("test_bypass"):
                    bypass = detector.test_bypass(f"https://{domain}", waf_name)
                    obs += f"Bypass results: {len(bypass.get('passed', []))}/{bypass.get('tested', 0)} payloads passed\n"
                    for p in bypass.get("passed", [])[:5]:
                        obs += f"  ✅ {p['payload'][:60]}\n"
                detector.save_results(domain)

            elif name == "run_response_diff":
                from response_differ import ResponseDiffer
                from session_manager import SessionManager
                sm = SessionManager(domain)
                differ = ResponseDiffer()
                url = args.get("url", "")
                method = args.get("method", "GET")
                atk_h = sm.get_auth_headers("attacker")
                vic_h = sm.get_auth_headers("victim")
                if not atk_h or not vic_h:
                    obs = "ERROR: Need both attacker and victim sessions. Use session_manager first."
                else:
                    result = differ.compare(url, atk_h, vic_h, method=method)
                    obs = f"IDOR test on {url}:\n"
                    obs += f"  Confirmed: {result['idor_confirmed']} (confidence: {result['confidence']}%)\n"
                    obs += f"  Severity: {result['severity']}\n"
                    if result.get("pii_leaked"):
                        obs += f"  PII leaked: {', '.join(p['type'] for p in result['pii_leaked'])}\n"
                    differ.save_findings(domain)

            elif name == "run_ws_test":
                from ws_tester import WSTester, WSDiscoverer
                ws_url = args.get("ws_url", "")
                tester = WSTester()
                if not ws_url:
                    discoverer = WSDiscoverer()
                    recon_dir = os.path.join(BASE_DIR, "recon", domain) if "BASE_DIR" not in dir() else os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "recon", domain)
                    endpoints = discoverer.discover_from_recon(recon_dir)
                    probed = discoverer.probe_common_paths(f"https://{domain}")
                    obs = f"WS Discovery: {len(endpoints)} from JS, {len(probed)} from probing\n"
                    for ep in (endpoints + [p["url"] for p in probed])[:3]:
                        result = tester.run_all_tests(ep, victim_id=args.get("victim_id", ""))
                        obs += f"  {ep}: {result.get('total_vulns', 0)} vulns\n"
                else:
                    from session_manager import SessionManager
                    sm = SessionManager(domain)
                    result = tester.run_all_tests(ws_url, auth_headers=sm.get_auth_headers("attacker"),
                                                  victim_id=args.get("victim_id", ""))
                    obs = f"WS test {ws_url}: {result.get('total_vulns', 0)} vulns found\n"
                    for test_name, test_result in result.get("tests", {}).items():
                        status = "🔴 VULN" if test_result.get("vulnerable") else "✅ OK"
                        obs += f"  {test_name}: {status}\n"
                tester.save_findings(domain)

            elif name == "run_param_mine":
                from param_miner import ParamMiner
                from session_manager import SessionManager
                sm = SessionManager(domain)
                miner = ParamMiner()
                url = args.get("url", "")
                method = args.get("method", "GET")
                headers = sm.get_auth_headers("attacker")
                results = miner.mine(url, method=method, headers=headers)
                high_params = [r for r in results if r.get("impact") in ("high", "medium")]
                obs = f"Param mining on {url}: {len(results)} discovered, {len(high_params)} high/medium impact\n"
                for r in high_params[:10]:
                    obs += f"  [{r['impact']}] {r['param']} ({r['vuln_class']})\n"
                miner.save_findings(domain)

            elif name == "run_wordlist_build":
                from wordlist_builder import WordlistBuilder
                builder = WordlistBuilder(domain, recon_dir=os.path.join(
                    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "recon", domain))
                # Install SecLists if needed
                seclists_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "wordlists", "seclists")
                if not os.path.isdir(seclists_dir):
                    WordlistBuilder.install_seclists()
                results = builder.build_all()
                obs = f"Wordlist build: {results.get('total', 0)} entries in master.txt\n"
                for k, v in results.items():
                    if k != "total":
                        obs += f"  {k}: {v}\n"

            elif name == "run_nuclei_gen":
                from nuclei_generator import NucleiGenerator
                gen = NucleiGenerator(domain)
                recon_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "recon", domain)
                generated = gen.generate(recon_dir=recon_dir)
                obs = f"Generated {len(generated)} nuclei templates:\n"
                for t in generated:
                    obs += f"  • {t}\n"

            elif name == "run_learn_hacktivity":
                from hacktivity_learner import HacktivityLearner
                learner = HacktivityLearner()
                program = args.get("program", domain)
                count = int(args.get("count", 25))
                knowledge = learner.learn_program(program, count=count)
                vc = knowledge.get("vuln_classes", {})
                obs = f"Learned from {knowledge.get('total_reports', 0)} Hacktivity reports:\n"
                for vc_name, vc_data in sorted(vc.items(), key=lambda x: x[1].get("count", 0), reverse=True)[:5]:
                    obs += f"  {vc_name}: {vc_data['count']} reports, avg ${vc_data.get('avg_bounty', 0):.0f}\n"
                strategy = learner.suggest_hunt_strategy()
                if strategy.get("priority_order"):
                    obs += f"Hunt priority: {', '.join(strategy['priority_order'][:5])}\n"

            # ── Advanced hunting tool dispatchers (Phase 2) ─────────────
            elif name == "run_race_test":
                from race_tester import RaceTester
                url = args.get("url", "")
                method = args.get("method", "POST")
                data = args.get("data", "")
                tester = RaceTester(threads=20)
                matches = tester.detect_race_type(url, method, data)
                result = tester.run(url, method, self._auth_headers(), data, attack_type="compare")
                obs = f"Race test on {url}: "
                if result.get("race_confirmed") or result.get("vuln_confirmed"):
                    obs += f"RACE CONDITION DETECTED!\n"
                    obs += f"  Parallel successes: {result.get('parallel_successes', result.get('success_count'))}\n"
                    obs += f"  Confidence: {result.get('confidence', result.get('severity'))}\n"
                else:
                    obs += f"No race condition found\n"
                if matches:
                    obs += f"  Race patterns: {', '.join(m['type'] for m in matches)}\n"
                tester.save_findings(domain)

            elif name == "run_ssrf_test":
                from ssrf_engine import SSRFEngine
                url = args.get("url", "")
                param = args.get("param", "")
                callback = args.get("callback", "")
                engine = SSRFEngine()
                result = engine.test_ssrf(url, param, self._auth_headers(), callback)
                obs = f"SSRF test on {url} (param={param}): "
                if result.get("ssrf_confirmed"):
                    obs += f"SSRF CONFIRMED! {len(result['hits'])} bypass(es) worked\n"
                    obs += f"  Severity: {result['severity']}\n"
                    for hit in result['hits'][:5]:
                        obs += f"  ✅ {hit['technique']}: {', '.join(hit.get('reasons', []))}\n"
                else:
                    obs += f"No SSRF ({result.get('tested', 0)} techniques tested)\n"
                engine.save_findings(domain)

            elif name == "run_api_security":
                from api_security import APISecurityTester
                test_type = args.get("test", "all")
                victim_id = args.get("victim_id", "999999")
                # Read recon to find API endpoints
                recon_dir = os.path.join(os.path.dirname(os.path.dirname(
                    os.path.abspath(__file__))), "recon", domain)
                api_endpoints = []
                urls_file = os.path.join(recon_dir, "all_urls.txt")
                if os.path.isfile(urls_file):
                    with open(urls_file) as f:
                        api_endpoints = [l.strip() for l in f if "/api/" in l][:50]
                tester = APISecurityTester(f"https://{domain}")
                obs = f"API Security scan ({test_type}):\n"
                if test_type in ("bola", "all") and api_endpoints:
                    bola = tester.test_bola(api_endpoints, self._auth_headers(), victim_id)
                    obs += f"  BOLA: {len(bola)} findings\n"
                if test_type in ("bfla", "all"):
                    bfla = tester.test_bfla(api_endpoints[:20], self._auth_headers())
                    obs += f"  BFLA: {len(bfla)} findings\n"
                tester.save_findings(domain)

            elif name == "run_cache_poison":
                from cache_poison import CachePoisonTester
                url = args.get("url", f"https://{domain}/")
                tester = CachePoisonTester()
                cdn = tester.detect_cdn(url)
                obs = f"Cache poison test on {url} (CDN: {cdn.get('cdn', 'unknown')}):\n"
                poison = tester.test_cache_poisoning(url, self._auth_headers())
                if poison.get("poisoned"):
                    obs += f"  CACHE POISONING CONFIRMED! {len(poison['hits'])} vector(s)\n"
                else:
                    obs += f"  Poisoning: {len(poison.get('hits', []))} partial hits\n"
                deception = tester.test_cache_deception(url, self._auth_headers())
                if deception.get("vulnerable"):
                    obs += f"  CACHE DECEPTION CONFIRMED! Auth pages cached\n"
                else:
                    obs += f"  Deception: not vulnerable\n"
                tester.save_findings(domain)

            elif name == "run_proto_pollution":
                from prototype_pollution import PrototypePollutionScanner
                url = args.get("url", "")
                method = args.get("method", "POST")
                scanner = PrototypePollutionScanner()
                result = scanner.run_all(url, method, self._auth_headers())
                obs = f"Prototype pollution on {url}: "
                if result.get("vulnerable"):
                    obs += f"VULNERABLE! {result['total_findings']} finding(s)\n"
                    for r in result.get("gadget_results", []):
                        obs += f"  ⚡ Gadget: {r['library']} → {r['chain']}\n"
                else:
                    obs += f"Not vulnerable\n"
                scanner.save_findings(domain)

            # ── Elite tool dispatchers (Phase 3) ──────────────────────
            elif name == "run_chain_escalate":
                from chain_engine import ChainEngine
                finding = json.loads(args.get("finding_json", "{}"))
                engine = ChainEngine(domain, self._auth_headers())
                result = engine.escalate(finding)
                obs = f"Chain escalation: "
                if result.get("escalated"):
                    obs += f"ESCALATED to {result['final_severity']}!\n"
                    for att in result.get("escalation_attempts", []):
                        if att.get("escalated"):
                            obs += f"  Chain: {att.get('chain', '')}\n"
                            obs += f"  Bounty multiplier: {att.get('bounty_multiplier', '')}\n"
                else:
                    obs += f"No escalation path found (trigger: {result.get('trigger', 'none')})\n"
                engine.save_chains()

            elif name == "run_generate_poc":
                from poc_generator import PoCGenerator
                finding = json.loads(args.get("finding_json", "{}"))
                gen = PoCGenerator()
                poc = gen.generate(finding)
                paths = gen.save_poc(poc, domain)
                obs = f"PoC generated for {poc['vuln_type']} ({poc['severity']}):\n"
                obs += f"  curl: {paths.get('curl', '')}\n"
                obs += f"  python: {paths.get('python', '')}\n"
                obs += f"  H1 report: {paths.get('report', '')}\n"

            elif name == "run_h2_smuggle":
                from h2_smuggler import H2Smuggler
                url = args.get("url", f"https://{domain}/")
                smuggler = H2Smuggler()
                result = smuggler.run_all(url, self._auth_headers())
                obs = f"H2 smuggling on {url} (HTTP/2: {result.get('http2_supported')}):\n"
                if result.get("vulnerable"):
                    obs += f"  REQUEST SMUGGLING DETECTED!\n"
                    for name_t, test in result.get("tests", {}).items():
                        if test.get("vulnerable"):
                            obs += f"  {test['type']}: VULNERABLE\n"
                            for ev in test.get("evidence", []):
                                obs += f"    {ev.get('indicator', str(ev))}\n"
                else:
                    obs += f"  Not vulnerable\n"
                smuggler.save_findings(domain)

            elif name == "run_graphql_deep":
                from graphql_deep import GraphQLDeepTester
                tester = GraphQLDeepTester(f"https://{domain}")
                result = tester.run_all(headers=self._auth_headers())
                obs = f"GraphQL deep scan:\n"
                if result.get("error"):
                    obs += f"  {result['error']}\n"
                else:
                    obs += f"  Endpoint: {result.get('endpoint', 'none')}\n"
                    intro = result.get("introspection", {})
                    if intro.get("enabled"):
                        obs += f"  Introspection: ENABLED ({len(intro.get('types', []))} types, {len(intro.get('mutations', []))} mutations)\n"
                    batch = result.get("batch_idor", {})
                    if batch.get("vulnerable"):
                        obs += f"  BATCH IDOR: {batch['leaked_records']} records leaked!\n"
                    dos = result.get("nested_dos", {})
                    if dos.get("vulnerable"):
                        obs += f"  Nested DoS: {dos.get('evidence', '')}\n"
                    fauth = result.get("field_auth", {})
                    if fauth.get("vulnerable"):
                        obs += f"  Field auth bypass: {len(fauth.get('unprotected_fields', []))} fields exposed\n"
                    obs += f"  Total findings: {result.get('total_findings', 0)}\n"
                tester.save_findings(domain)

            elif name == "run_monitor":
                from monitor import AttackSurfaceMonitor
                mon = AttackSurfaceMonitor(domain)
                result = mon.run_full_check()
                new_subs = result.get("subdomains", {}).get("new", [])
                changed = result.get("endpoints", {}).get("changed", [])
                obs = f"Attack surface monitor:\n"
                obs += f"  Total subdomains: {result.get('subdomains', {}).get('total', 0)}\n"
                if new_subs:
                    obs += f"  NEW SUBDOMAINS ({len(new_subs)}): {', '.join(new_subs[:10])}\n"
                if changed:
                    obs += f"  Changed endpoints: {len(changed)}\n"
                obs += f"  Total changes: {result.get('total_changes', 0)}\n"

            elif name == "run_git_recon":
                from git_recon import GitRecon
                org = args.get("org", domain.split(".")[0])
                recon = GitRecon()
                result = recon.run_full_scan(org)
                obs = f"GitHub recon on {org}:\n"
                obs += f"  Repos found: {result.get('repos_found', 0)}\n"
                obs += f"  Secrets found: {result.get('secrets_found', 0)}\n"
                obs += f"  CRITICAL secrets: {result.get('critical_secrets', 0)}\n"
                if result.get("findings"):
                    for f in result["findings"][:5]:
                        obs += f"  [{f.get('severity')}] {f.get('description')}: {f.get('value', '')}\n"
                recon.save_findings(domain)

            # ── Production tool dispatchers ──────────────────────────
            elif name == "run_generate_report":
                from report_finalizer import ReportFinalizer
                min_sev = args.get("min_severity", "MEDIUM")
                report = ReportFinalizer(domain)
                text = report.generate(min_severity=min_sev)
                report_path = report.save()
                h1_paths = report.save_h1_submissions()
                counts = report.severity_summary()
                obs = f"Report generated:\n"
                obs += f"  Total findings: {sum(counts.values())}\n"
                obs += f"  CRITICAL: {counts.get('CRITICAL', 0)}, HIGH: {counts.get('HIGH', 0)}\n"
                obs += f"  Report saved: {report_path}\n"
                if h1_paths:
                    obs += f"  H1 submissions: {len(h1_paths)} files\n"

            elif name == "run_auth_login":
                from auth_manager import AuthManager
                login_url = args.get("login_url", "")
                auth = AuthManager(domain)
                if not login_url:
                    login_url = auth.find_login_page(f"https://{domain}")
                username = os.environ.get("HUNT_USERNAME", "")
                password = os.environ.get("HUNT_PASSWORD", "")
                if not username:
                    obs = "No HUNT_USERNAME env var set. Set credentials first.\n"
                else:
                    result = auth.login(login_url, username, password)
                    obs = f"Auth login to {login_url}:\n"
                    if result.get("success"):
                        obs += f"  SUCCESS! Auth type: {result['auth_type']}\n"
                        obs += f"  Tokens: {len(result.get('tokens', {}))}\n"
                        # Update dispatcher auth headers
                        new_headers = auth.get_auth_headers()
                        if new_headers.get("Cookie"):
                            self.default_cookies = new_headers["Cookie"]
                        obs += f"  Auth headers updated for all tools\n"
                    else:
                        obs += f"  FAILED: {result.get('error', 'unknown')}\n"

            # ── Final expansion dispatchers ────────────────────────
            elif name == "run_xxe_scan":
                from xxe_scanner import XXEScanner
                url = args.get("url", f"https://{domain}")
                method = args.get("method", "POST")
                scanner = XXEScanner()
                result = scanner.test_endpoint(url, method, self._auth_headers())
                obs = f"XXE scan on {url}:\n"
                if result.get("vulnerable"):
                    for f in result.get("findings", []):
                        if f.get("evidence"):
                            obs += f"  {f['payload']}: {f['evidence']} — {f.get('severity', '')}\n"
                else:
                    obs += f"  Not vulnerable\n"
                scanner.save_findings(domain)

            elif name == "run_open_redirect":
                from open_redirect import OpenRedirectScanner
                url = args.get("url", f"https://{domain}")
                scanner = OpenRedirectScanner()
                if "?" in url:
                    result = scanner.scan_url(url, self._auth_headers())
                else:
                    result = scanner.scan_domain(url, self._auth_headers())
                obs = f"Open redirect scan:\n"
                if result.get("vulnerable") or result.get("total", 0) > 0:
                    vulns = result.get("findings", result.get("vulnerable", []))
                    if isinstance(vulns, list):
                        for v in vulns[:5]:
                            obs += f"  {v.get('url', v.get('param', ''))} → {v.get('redirect_to', v.get('payload', ''))[:60]}\n"
                    obs += f"  Chain to OAuth for CRITICAL escalation\n"
                else:
                    obs += f"  No open redirects found\n"
                scanner.save_findings(domain)

            elif name == "run_file_upload_test":
                from file_upload import FileUploadTester
                url = args.get("url", "")
                field = args.get("field", "file")
                tester = FileUploadTester()
                result = tester.test_upload(url, field, self._auth_headers())
                obs = f"File upload test on {url}:\n"
                if result.get("vulnerable"):
                    for f in result.get("findings", []):
                        if f.get("severity"):
                            obs += f"  {f.get('type', 'UPLOAD')}: {f.get('filename', '')} — {f['severity']}\n"
                else:
                    obs += f"  No dangerous uploads accepted\n"
                tester.save_findings(domain)

            elif name == "run_path_traversal":
                from path_traversal import PathTraversalScanner
                url = args.get("url", f"https://{domain}")
                scanner = PathTraversalScanner()
                result = scanner.test_url(url, self._auth_headers())
                obs = f"Path traversal scan on {url}:\n"
                if result.get("vulnerable"):
                    for f in result.get("findings", []):
                        obs += f"  TRAVERSAL on param '{f['param']}': {f['evidence']} — CRITICAL\n"
                else:
                    obs += f"  Not vulnerable\n"
                scanner.save_findings(domain)

            elif name == "run_business_logic_test":
                from business_logic import BusinessLogicTester
                tester = BusinessLogicTester(f"https://{domain}")
                result = tester.test_all(self._auth_headers())
                obs = f"Business logic testing on {domain}:\n"
                eps = result.get("endpoints", {})
                obs += f"  Cart endpoints: {len(eps.get('cart', []))}\n"
                obs += f"  Coupon endpoints: {len(eps.get('coupon', []))}\n"
                price = result.get("price", {})
                if price.get("vulnerable"):
                    obs += f"  PRICE MANIPULATION — negative/zero price accepted!\n"
                qty = result.get("quantity", {})
                if qty.get("vulnerable"):
                    obs += f"  QUANTITY ABUSE — negative total achieved!\n"
                coupon = result.get("coupon", {})
                if coupon.get("vulnerable"):
                    obs += f"  COUPON ABUSE — stacking/negative discount!\n"
                wf = result.get("workflow", {})
                if wf.get("vulnerable"):
                    obs += f"  WORKFLOW BYPASS — checkout steps skippable!\n"
                obs += f"  Findings: {result.get('total_findings', 0)}\n"
                tester.save_findings(domain)

            # ── Advanced attack dispatchers ──────────────────────────
            elif name == "run_ssti_scan":
                from ssti_scanner import SSTIScanner
                url = args.get("url", f"https://{domain}")
                scanner = SSTIScanner()
                result = scanner.test_url(url, self._auth_headers())
                obs = f"SSTI scan on {url}:\n"
                if result.get("vulnerable"):
                    for f in result["findings"]:
                        obs += f"  ENGINE: {f['engine']} on param '{f['param']}'\n"
                        if f.get("rce"):
                            obs += f"  RCE CONFIRMED! Payload: {f.get('rce_payload', '')[:60]}\n"
                        obs += f"  Severity: {f['severity']}\n"
                else:
                    obs += f"  Not vulnerable ({result.get('params_tested', 0)} params tested)\n"
                scanner.save_findings(domain)

            elif name == "run_host_header_attack":
                from host_header import HostHeaderAttack
                attacker = HostHeaderAttack(f"https://{domain}")
                result = attacker.test_all(self._auth_headers())
                obs = f"Host header attacks on {domain}:\n"
                reset = result.get("password_reset", {})
                if reset.get("vulnerable"):
                    obs += f"  PASSWORD RESET POISONING — Host header reflected in reset link!\n"
                cache = result.get("cache_poisoning", {})
                if cache.get("vulnerable"):
                    obs += f"  CACHE POISONING — Host header poisons CDN cache!\n"
                ssrf = result.get("ssrf", {})
                if ssrf.get("vulnerable"):
                    obs += f"  SSRF via Host — cloud metadata accessible!\n"
                obs += f"  Findings: {result.get('total_findings', 0)}\n"
                attacker.save_findings(domain)

            elif name == "run_oauth_test":
                from oauth_tester import OAuthTester
                tester = OAuthTester(f"https://{domain}")
                result = tester.test_all(self._auth_headers())
                obs = f"OAuth testing on {domain}:\n"
                obs += f"  Endpoints found: {result.get('endpoints_found', 0)}\n"
                redir = result.get("redirect_uri", {})
                if redir.get("vulnerable"):
                    obs += f"  REDIRECT_URI BYPASS — token theft possible!\n"
                state = result.get("missing_state", {})
                if state.get("vulnerable"):
                    obs += f"  MISSING STATE — OAuth CSRF possible\n"
                scope = result.get("scope_escalation", {})
                if scope.get("vulnerable"):
                    obs += f"  SCOPE ESCALATION — admin scope accepted\n"
                obs += f"  Findings: {result.get('total_findings', 0)}\n"
                tester.save_findings(domain)

            # ── Intelligence layer dispatchers ─────────────────────
            elif name == "run_subdomain_takeover":
                from subdomain_takeover import SubdomainTakeover
                scanner = SubdomainTakeover()
                result = scanner.scan_domain(domain)
                obs = f"Subdomain takeover scan:\n"
                obs += f"  Checked: {result.get('total_checked', 0)}\n"
                if result.get("vulnerable"):
                    obs += f"  VULNERABLE ({len(result['vulnerable'])}):\n"
                    for v in result["vulnerable"]:
                        obs += f"    {v['subdomain']} → {v['cname']} ({v['service']})\n"
                        obs += f"    Evidence: {v.get('evidence', '')}\n"
                else:
                    obs += f"  No takeovers found\n"
                if result.get("dangling"):
                    obs += f"  Dangling CNAMEs (monitor): {len(result['dangling'])}\n"
                scanner.save_findings(domain)

            elif name == "run_jwt_analysis":
                from jwt_analyzer import JWTAnalyzer
                token = args.get("token", "")
                verify_url = args.get("verify_url", "")
                analyzer = JWTAnalyzer()
                result = analyzer.analyze_token(token, verify_url, self._auth_headers())
                decoded = result.get("decoded", {})
                obs = f"JWT analysis:\n"
                obs += f"  Algorithm: {result.get('algorithm', 'unknown')}\n"
                obs += f"  Claims: {json.dumps(decoded.get('payload', {}), default=str)[:200]}\n"
                brute = result.get("brute_force", {})
                if brute.get("cracked"):
                    obs += f"  SECRET CRACKED: '{brute['secret']}' — CRITICAL\n"
                alg = result.get("alg_confusion", {})
                if alg.get("vulnerable"):
                    obs += f"  ALG CONFUSION: alg=none ACCEPTED — CRITICAL\n"
                claims = result.get("claim_tampering", {})
                if claims.get("vulnerable"):
                    obs += f"  CLAIM TAMPERING: admin escalation possible — CRITICAL\n"
                if result.get("security_issues"):
                    for issue in result["security_issues"]:
                        obs += f"  Issue: {issue}\n"
                analyzer.save_findings(domain)

            elif name == "run_api_discovery":
                from api_discovery import APIDiscovery
                disco = APIDiscovery(f"https://{domain}")
                result = disco.discover(self._auth_headers())
                obs = f"API discovery:\n"
                if result.get("swagger"):
                    for s in result["swagger"]:
                        obs += f"  Swagger: {s['url']} ({s.get('endpoint_count', '?')} endpoints)\n"
                if result.get("graphql"):
                    for g in result["graphql"]:
                        intro = " (INTROSPECTION ENABLED!)" if g.get("introspection") else ""
                        obs += f"  GraphQL: {g['url']}{intro}\n"
                if result.get("debug"):
                    for d in result["debug"]:
                        obs += f"  Debug: {d['url']} (marker: {d.get('marker', '')})\n"
                obs += f"  JS endpoints found: {len(result.get('js_endpoints', []))}\n"
                obs += f"  Total endpoints: {result.get('total_endpoints', 0)}\n"
                disco.save_findings(domain)

            elif name == "run_blind_xss":
                from blind_xss import BlindXSSHunter
                url = args.get("url", f"https://{domain}")
                hunter = BlindXSSHunter()
                result = hunter.inject_all(url, self._auth_headers())
                obs = f"Blind XSS deployment:\n"
                obs += f"  Injection points: {result.get('injection_points', 0)}\n"
                obs += f"  Payloads sent: {result.get('payloads_sent', 0)}\n"
                obs += f"  Successful injections: {result.get('successful_injections', 0)}\n"
                if result.get("reflected"):
                    obs += f"  REFLECTED XSS: {result['reflected']} points (non-blind!)\n"
                obs += f"  Callback: {result.get('callback_url', 'NOT SET')}\n"
                obs += f"  Note: {result.get('note', '')}\n"
                hunter.save_findings(domain)

            elif name == "run_2fa_bypass":
                from twofa_bypass import TwoFABypass
                tester = TwoFABypass()
                result = tester.test_all(f"https://{domain}", self._auth_headers())
                obs = f"2FA bypass testing:\n"
                obs += f"  Endpoints found: {len(result.get('endpoints_found', []))}\n"
                direct = result.get("direct_access", {})
                if direct.get("vulnerable"):
                    obs += f"  DIRECT ACCESS BYPASS: {len(direct['bypassed'])} pages accessible without 2FA!\n"
                rate = result.get("rate_limit", {})
                if rate.get("vulnerable"):
                    obs += f"  NO RATE LIMIT on OTP — brutable!\n"
                obs += f"  Total findings: {result.get('total_findings', 0)}\n"
                tester.save_findings(domain)

            elif name == "run_hunt_intel":
                from hunt_intel import HuntIntel
                intel = HuntIntel()
                tech = args.get("tech_stack", "")
                tech_list = [t.strip() for t in tech.split(",")] if tech else []
                strategy = intel.suggest_strategy(domain, tech_list)
                history = intel.get_target_history(domain)
                stats = intel.get_stats_summary()
                obs = f"Hunt intelligence:\n"
                obs += f"  Total hunts: {stats.get('total_hunts', 0)}, "
                obs += f"Findings: {stats.get('total_findings', 0)}\n"
                if history.get("previous_hunts", 0) > 0:
                    obs += f"  Previous hunts on {domain}: {history['previous_hunts']}\n"
                    obs += f"  Known vulns: {', '.join(history.get('known_vuln_types', [])[:5])}\n"
                if strategy.get("recommended_tools"):
                    obs += f"  Recommended tools: "
                    obs += ", ".join(t['name'] for t in strategy['recommended_tools'][:5])
                    obs += "\n"
                if strategy.get("skip_tools"):
                    obs += f"  Skip (low ROI): {', '.join(strategy['skip_tools'][:5])}\n"
                if strategy.get("expected_vuln_types"):
                    obs += f"  Expected vulns: {', '.join(strategy['expected_vuln_types'][:5])}\n"

            # ── End all tool dispatchers ────────────────────────────────

            elif name == "read_recon_summary":
                obs = self._read_recon_files(domain)

            elif name == "read_findings_summary":
                obs = self._read_findings_files(domain)

            elif name == "update_working_memory":
                notes = args.get("notes", "")
                self.memory.working_memory = notes
                self.memory.save()
                return f"Working memory updated ({len(notes)} chars)."

            elif name == "finish":
                return f"FINISH: {args.get('verdict', 'Hunt complete.')}"

            else:
                return f"Unknown tool: {name}"

        except Exception as exc:
            tb = traceback.format_exc()
            return f"Tool {name} raised exception: {exc}\n{tb[:500]}"

        elapsed = round(time.time() - t0, 1)
        obs_full = f"{obs}\n\n[{name} completed in {elapsed}s]"

        # Update memory
        self.memory.add_observation(name, obs_full)
        self.memory.completed_steps.append(name)
        self.memory.step_count += 1

        # Classify any critical/high findings into findings_log
        self._classify_obs(name, obs_full)
        self.memory.save()

        return obs_full

    # ── Observation formatters ──────────────────────────────────────────────

    def _summarize_recon(self, domain: str, ok: bool) -> str:
        h = _h()
        recon_dir = h._resolve_recon_dir(domain)
        lines = [f"run_recon: {'OK' if ok else 'PARTIAL'}"]

        # Count live hosts
        for fn in ("live/httpx_full.txt", "httpx_full.txt"):
            fp = os.path.join(recon_dir, fn)
            if os.path.isfile(fp):
                count = sum(1 for _ in open(fp) if _.strip())
                lines.append(f"Live hosts: {count}")
                break

        # Count resolved subdomains
        for fn in ("resolved.txt", "all.txt"):
            fp = os.path.join(recon_dir, fn)
            if os.path.isfile(fp):
                count = sum(1 for _ in open(fp) if _.strip())
                lines.append(f"Subdomains: {count}")
                break

        # Tech detections
        for fn in ("tech_priority.txt", "tech.txt"):
            fp = os.path.join(recon_dir, fn)
            if os.path.isfile(fp):
                techs = [l.strip() for l in open(fp) if l.strip()][:10]
                lines.append(f"Tech detected: {', '.join(techs)}")
                break

        # Parameterized URLs
        for fn in ("urls/with_params.txt", "params/with_params.txt"):
            fp = os.path.join(recon_dir, fn)
            if os.path.isfile(fp):
                count = sum(1 for _ in open(fp) if _.strip())
                lines.append(f"Parameterized URLs: {count}")
                break

        return "\n".join(lines)

    def _summarize_findings(self, domain: str, label: str, ok: bool) -> str:
        h = _h()
        findings_dir = h._resolve_findings_dir(domain, create=False)
        lines = [f"{label}: {'OK' if ok else 'ran (check manually)'}"]

        # Walk findings dir for any .txt with content
        if findings_dir and os.path.isdir(findings_dir):
            for root, _, files in os.walk(findings_dir):
                for fn in files:
                    if not fn.endswith(".txt"):
                        continue
                    fp = os.path.join(root, fn)
                    try:
                        content = Path(fp).read_text(errors="replace")
                        if any(kw in content.lower() for kw in
                               ("critical", "high", "vulnerable", "injectable",
                                "rce", "sqli", "open redirect", "exposed", "default cred")):
                            head = content[:400].replace("\n", " ")
                            lines.append(f"  [{fn}] {head}")
                    except Exception:
                        pass

        if len(lines) == 1:
            lines.append("  No HIGH/CRITICAL findings in artifacts (check logs above for details).")
        return "\n".join(lines[:20])

    def _summarize_params(self, domain: str, ok: bool) -> str:
        h = _h()
        recon_dir  = h._resolve_recon_dir(domain)
        params_dir = os.path.join(recon_dir, "params")
        lines = [f"run_param_discovery: {'OK' if ok else 'partial'}"]
        for fn in ("paramspider.txt", "arjun.json"):
            fp = os.path.join(params_dir, fn)
            if os.path.isfile(fp):
                count = sum(1 for _ in open(fp) if _.strip())
                lines.append(f"  {fn}: {count} lines")
        return "\n".join(lines)

    def _summarize_post_params(self, domain: str, ok: bool) -> str:
        h = _h()
        recon_dir  = h._resolve_recon_dir(domain)
        params_dir = os.path.join(recon_dir, "params")
        lines = [f"run_post_param_discovery: {'found POST params' if ok else 'no POST params found'}"]
        fp = os.path.join(params_dir, "post_params.json")
        if os.path.isfile(fp):
            try:
                data = json.loads(Path(fp).read_text())
                for url, info in list(data.items())[:8]:
                    params = ", ".join(info.get("params", [])[:6])
                    lines.append(f"  POST {url}  →  [{params}]")
            except Exception:
                pass
        return "\n".join(lines)

    def _read_recon_files(self, domain: str) -> str:
        h = _h()
        recon_dir = h._resolve_recon_dir(domain)
        parts = []

        for label, fn in [
            ("Live hosts (sample)",    "httpx_full.txt"),
            ("Tech priority",          "tech_priority.txt"),
            ("Parameterized URLs",     "urls/with_params.txt"),
            ("All URLs (sample)",      "urls/all.txt"),
        ]:
            fp = os.path.join(recon_dir, fn)
            if os.path.isfile(fp):
                lines = [l.strip() for l in open(fp) if l.strip()]
                count = len(lines)
                sample = lines[:20]
                parts.append(f"=== {label} ({count} total) ===\n" + "\n".join(sample))

        return "\n\n".join(parts) if parts else "No recon data found. Run run_recon first."

    def _read_findings_files(self, domain: str) -> str:
        h = _h()
        findings_dir = h._resolve_findings_dir(domain, create=False)
        if not findings_dir or not os.path.isdir(findings_dir):
            return "No findings directory. Run vulnerability scans first."

        parts = []
        for root, _, files in os.walk(findings_dir):
            for fn in sorted(files):
                if not fn.endswith((".txt", ".json")):
                    continue
                fp = os.path.join(root, fn)
                try:
                    content = Path(fp).read_text(errors="replace")
                    if content.strip():
                        rel = os.path.relpath(fp, findings_dir)
                        parts.append(f"=== {rel} ===\n{content[:800]}")
                except Exception:
                    pass

        if not parts:
            return "Findings directory exists but is empty."
        combined = "\n\n".join(parts)
        # Truncate to avoid blowing context
        if len(combined) > MAX_CTX_CHARS:
            combined = combined[:MAX_CTX_CHARS] + "\n...[truncated]"
        return combined

    def _classify_obs(self, tool: str, obs: str) -> None:
        """Extract severity labels from observation text and add to findings_log."""
        obs_l = obs.lower()
        if any(kw in obs_l for kw in ("rce_confirmed", "injectable", "critical")):
            sev = "CRITICAL"
        elif any(kw in obs_l for kw in ("high", "sql injection", "rce", "default cred")):
            sev = "HIGH"
        elif any(kw in obs_l for kw in ("medium", "exposed", "open redirect", "cors")):
            sev = "MEDIUM"
        elif any(kw in obs_l for kw in ("low", "info")):
            sev = "LOW"
        else:
            return  # not a finding, skip

        # Take first relevant line as summary
        for ln in obs.splitlines():
            if any(kw in ln.lower() for kw in
                   ("critical", "high", "injectable", "rce", "exposed", "found", "medium", "sql")):
                self.memory.add_finding(tool, sev, ln.strip()[:300])
                break


# ──────────────────────────────────────────────────────────────────────────────
#  Core ReAct agent  (Ollama native tool calling)
# ──────────────────────────────────────────────────────────────────────────────

# ──────────────────────────────────────────────────────────────────────────────
#  Loop Detector  (ctf-agent technique: signature hashing, sliding window 12)
# ──────────────────────────────────────────────────────────────────────────────

class LoopDetector:
    """
    Detects when the agent is repeating the same tool call in a loop.
    Sliding window of last 12 tool signatures.
    Warn at 3 repetitions, force direction change at 5.
    Signature = tool_name + first 300 chars of serialised args.
    """
    WINDOW = 12
    WARN_AT  = 3
    BREAK_AT = 5

    def __init__(self):
        self._history: list[str] = []
        self._counts:  dict[str, int] = {}

    def record(self, tool: str, args: dict) -> tuple[bool, bool]:
        """
        Record a tool call. Returns (warn, must_break).
        warn=True at WARN_AT repeats; must_break=True at BREAK_AT.
        """
        sig = tool + ":" + json.dumps(args, sort_keys=True)[:300]
        self._history.append(sig)
        if len(self._history) > self.WINDOW:
            evicted = self._history.pop(0)
            self._counts[evicted] = max(0, self._counts.get(evicted, 0) - 1)
        self._counts[sig] = self._counts.get(sig, 0) + 1
        n = self._counts[sig]
        return n >= self.WARN_AT, n >= self.BREAK_AT

    def reset(self) -> None:
        self._history.clear()
        self._counts.clear()


# ──────────────────────────────────────────────────────────────────────────────
#  JSONL Tracer  (ctf-agent technique: append-only, immediate flush, tail -f)
# ──────────────────────────────────────────────────────────────────────────────

class AgentTracer:
    """
    Append-only JSONL event log — one JSON object per line, flushed immediately.
    `tail -f session.jsonl` gives live stream of what the agent is doing.
    """

    def __init__(self, log_path: str):
        self.log_path = log_path
        Path(log_path).parent.mkdir(parents=True, exist_ok=True)
        self._f = open(log_path, "a", buffering=1)  # line-buffered

    def _write(self, event: dict) -> None:
        event.setdefault("ts", datetime.now().isoformat())
        self._f.write(json.dumps(event) + "\n")
        self._f.flush()

    def tool_call(self, tool: str, args: dict, step: int) -> None:
        self._write({"event": "tool_call", "step": step, "tool": tool, "args": args})

    def tool_result(self, tool: str, result: str, elapsed: float, step: int) -> None:
        self._write({"event": "tool_result", "step": step, "tool": tool,
                     "elapsed_s": elapsed, "result_preview": result[:400]})

    def loop_warn(self, tool: str, count: int, step: int) -> None:
        self._write({"event": "loop_warn", "step": step, "tool": tool, "count": count})

    def loop_break(self, tool: str, step: int) -> None:
        self._write({"event": "loop_break", "step": step, "tool": tool})

    def bump(self, message: str, step: int) -> None:
        self._write({"event": "bump", "step": step, "message": message})

    def finding(self, severity: str, tool: str, text: str) -> None:
        self._write({"event": "finding", "severity": severity, "tool": tool, "text": text[:300]})

    def finish(self, verdict: str, step: int, elapsed_mins: float) -> None:
        self._write({"event": "finish", "step": step,
                     "elapsed_mins": elapsed_mins, "verdict": verdict})

    def close(self) -> None:
        self._f.close()


# ──────────────────────────────────────────────────────────────────────────────
#  Multi-model racer  (ctf-agent: asyncio FIRST_COMPLETED pattern)
# ──────────────────────────────────────────────────────────────────────────────

def race_analysis(prompt: str, models: list[str], client,
                  system: str = "", timeout: int = 120) -> str:
    """
    Ask multiple Ollama models the same analysis question.
    Return whichever completes first with a non-empty answer.
    Used for: triage decisions, next-action advice, finding classification.
    Falls back to sequential if only one model available.
    """
    import threading

    result_holder: dict[str, str] = {}
    done_event = threading.Event()

    def _call(model: str) -> None:
        try:
            resp = client.chat(
                model=model,
                messages=[
                    {"role": "system", "content": system or AGENT_SYSTEM},
                    {"role": "user",   "content": prompt},
                ],
                options={"num_predict": 800, "temperature": 0.1, "num_ctx": 8192},
            )
            text = (resp.get("message", {}).get("content") or "").strip()
            if text and not done_event.is_set():
                result_holder["winner"] = model
                result_holder["text"]   = text
                done_event.set()
        except Exception:
            pass

    threads = [threading.Thread(target=_call, args=(m,), daemon=True) for m in models]
    for t in threads:
        t.start()
    done_event.wait(timeout=timeout)

    if "text" in result_holder:
        winner = result_holder["winner"]
        print(f"{DIM}[Race] Winner: {winner}{NC}", flush=True)
        return result_holder["text"]

    # Sequential fallback
    for m in models:
        try:
            resp = client.chat(
                model=m,
                messages=[
                    {"role": "system", "content": system or AGENT_SYSTEM},
                    {"role": "user",   "content": prompt},
                ],
                options={"num_predict": 800, "temperature": 0.1, "num_ctx": 8192},
            )
            text = (resp.get("message", {}).get("content") or "").strip()
            if text:
                return text
        except Exception:
            continue
    return ""


AGENT_SYSTEM = """\
You are an elite autonomous bug bounty hunter. You have 25+ years of experience finding CRITICAL vulnerabilities \
that pay $10K-$100K bounties. You operate within authorized bug bounty programs.

You have tools that execute REAL security scans. Use them in the OPTIMAL order below.

## MANDATORY EXECUTION SEQUENCE (follow this order)

### Phase 1: Intelligence Gathering (steps 1-4)
1. run_learn_hacktivity — Learn what worked before on this program. Study disclosed reports.
2. run_recon — Full subdomain enumeration + live host discovery.
3. read_recon_summary — Understand the attack surface, tech stack, endpoints.
4. run_wordlist_build — Generate target-specific wordlists from recon data + install SecLists.

### Phase 2: Pre-Hunt Setup (steps 5-6)
5. run_waf_detect — MUST detect WAF before active testing. Adapt payloads if WAF found.
6. run_nuclei_gen — Generate custom nuclei templates from tech stack → run_vuln_scan.

### Phase 3: Active Hunting — HIGH-PAYING VULNS (steps 7+)
PRIORITY ORDER (by bounty payout):

| Priority | Tool | When |
|----------|------|------|
| #1 | run_api_security | REST API found — BOLA/BFLA/mass assignment (#1 OWASP API) |
| #2 | run_response_diff | API endpoints with user IDs — IDOR field-level diff |
| #3 | run_race_test | Financial/state-changing endpoints — double-spend, limit-overrun |
| #4 | run_ssrf_test | URL/redirect/callback params — 50+ bypass + cloud metadata chain |
| #5 | run_rce_scan | Java/Tomcat/JBoss/Spring detected |
| #6 | run_cms_exploit | Drupal/WordPress detected |
| #7 | run_cache_poison | Target behind CDN — cache poisoning + deception |
| #8 | run_sqlmap_targeted | Parameterized URLs found |
| #9 | run_proto_pollution | Node.js/Express — __proto__ injection → RCE gadgets |
| #10 | run_param_mine | High-value endpoints — hidden debug/admin params |
| #11 | run_ws_test | WebSocket endpoints found (bypass WAFs!) |
| #12 | run_api_fuzz | API endpoints with numeric IDs |
| #13 | run_cors_check | Authenticated API endpoints present |
| #14 | run_jwt_audit | JWT tokens in cookies/headers |
| #15 | run_secret_hunt | Always worth running for leaked keys |
| #16 | run_js_analysis | JS bundles found during recon |
| #17 | run_post_param_discovery | Login forms / POST endpoints |
| #18 | run_graphql_deep | GraphQL detected — batch IDOR, nested DoS, field auth |
| #19 | run_h2_smuggle | Reverse proxy detected — CL.TE/TE.CL desync |
| #20 | run_git_recon | Org name known — leaked secrets in GitHub |
| #21 | run_monitor | Start of hunt — detect attack surface changes |

### Phase 3.5: Escalation (run AFTER every finding)
| Always | run_chain_escalate | After ANY finding — auto-chain to higher severity |
| Always | run_generate_poc | After CONFIRMED finding — generate curl/Python PoC + H1 report |

### Phase 4: Finalize
- run_generate_report — MANDATORY: dedup, sort, and generate H1-quality report
- update_working_memory with all findings
- read_findings_summary to review everything
- finish with verdict

NOTE: If HUNT_USERNAME is set, run run_auth_login BEFORE Phase 3 (authenticated testing).

## CRITICAL RULES
1. SCOPE: Every URL MUST be in-scope. Use run_scope_check if unsure. NEVER test out-of-scope.
2. NEVER ask the user anything. YOU make ALL decisions.
3. If tool fails → skip it, continue to next. NEVER stop the pipeline.
4. If WAF blocks (403) → use bypass payloads from run_waf_detect results.
5. A→B CHAINS: If IDOR found → immediately test PUT/DELETE on same endpoint.
   If SSRF found → hit cloud metadata (169.254.169.254). Chain = Critical severity.
6. 5 MINUTES MAX per endpoint. No signal → rotate.
7. update_working_memory after EVERY significant discovery.
8. DO NOT repeat tools already completed unless new attack surface discovered.
9. Focus on HIGH/CRITICAL severity only. Informational findings waste bounty reviewer time.
10. Real hackers find IDOR, auth bypass, SSRF, RCE — not just XSS and open redirects.
11. ALWAYS run run_chain_escalate after ANY HIGH/CRITICAL finding — chains multiply bounties 3-20x.
12. ALWAYS run run_generate_poc after confirming any vulnerability — reproducible PoC = instant triage.

Think step by step. Pick the highest-ROI next action given what you know."""


class ReActAgent:
    """
    Built-in ReAct loop using Ollama native tool calling.
    Works without LangGraph installed — just needs `pip install ollama`.
    """

    MIN_STEPS_BEFORE_FINISH = 6  # persistence: must run at least N tools before finish allowed

    def __init__(self, domain: str, memory: HuntMemory,
                 dispatcher: ToolDispatcher,
                 max_steps: int = 20,
                 time_budget_hours: float = 2.0,
                 model: str | None = None,
                 tracer: AgentTracer | None = None):
        self.domain     = domain
        self.memory     = memory
        self.dispatcher = dispatcher
        self.max_steps  = max_steps
        self.time_start = time.time()
        self.time_budget_secs = time_budget_hours * 3600
        self.done       = False
        self.verdict    = ""

        # ctf-agent techniques
        self.loop_detector = LoopDetector()
        self.tracer        = tracer  # set externally after session_file is known
        self.bump_file     = ""      # set by run_agent_hunt — path to bump file

        # racing models (analysis + triage) — baron-llm races qwen3 on quick decisions
        self._race_models: list[str] = []

        if not _OLLAMA_OK:
            raise RuntimeError("Ollama Python package not installed: pip install ollama")

        self.client = _ollama_lib.Client(host=OLLAMA_HOST)
        self.model  = model or self._pick_tool_capable_model()
        if not self.model:
            raise RuntimeError("No Ollama model available. Pull one: ollama pull qwen2.5:32b")

        # Build race roster: primary model + baron-llm if available and different
        try:
            available = [m.model for m in self.client.list().models]
            if "baron-llm:latest" in available and "baron-llm:latest" != self.model:
                self._race_models = [self.model, "baron-llm:latest"]
            else:
                self._race_models = [self.model]
        except Exception:
            self._race_models = [self.model]

        print(f"{GREEN}[Agent] ReAct loop online — model: {BOLD}{self.model}{NC}", flush=True)
        race_note = f"  race_models={self._race_models}" if len(self._race_models) > 1 else ""
        print(f"{DIM}[Agent] max_steps={max_steps}  budget={time_budget_hours}h  "
              f"tool_calling=native{race_note}{NC}", flush=True)

    def _pick_tool_capable_model(self) -> str | None:
        """Prefer models with confirmed Ollama tool-calling support."""
        tool_capable_first = [
            "qwen3-coder-64k:latest",
            "qwen3-coder:30b",
            "qwen2.5:32b",
            "qwen2.5-coder:32b",
            "qwen3:30b-a3b",
            "qwen3:14b",
            "qwen3:8b",
            "mistral:7b-instruct-v0.3-q8_0",
        ]
        try:
            available = [m.model for m in self.client.list().models]
        except Exception:
            return None

        for pref in tool_capable_first:
            if pref in available:
                return pref
        # Fall back to first available
        return available[0] if available else None

    def _build_context(self) -> str:
        """Build the current state block that prefixes every LLM message."""
        elapsed_mins = round((time.time() - self.time_start) / 60, 1)
        budget_mins  = round(self.time_budget_secs / 60, 1)
        remaining    = round((self.time_budget_secs - (time.time() - self.time_start)) / 60, 1)

        completed = list(dict.fromkeys(self.memory.completed_steps))
        ctx_parts = [
            f"## Autonomous Hunt — {self.domain}",
            f"Step {self.memory.step_count + 1}/{self.max_steps}  "
            f"| Elapsed {elapsed_mins}m / {budget_mins}m budget  "
            f"| {remaining}m remaining",
            "",
            f"## Completed steps ({len(completed)})",
            ", ".join(completed) if completed else "(none yet)",
            "",
            "## Working memory (your notes)",
            self.memory.working_memory or "(empty — use update_working_memory to take notes)",
            "",
            "## Findings so far",
            self.memory.findings_summary(),
            "",
            "## Recent tool outputs (last 3)",
            self.memory.recent_observations(3),
        ]
        return "\n".join(ctx_parts)

    def _check_bump(self) -> str | None:
        """Check if operator has injected guidance via bump file."""
        if not self.bump_file or not os.path.isfile(self.bump_file):
            return None
        try:
            msg = Path(self.bump_file).read_text().strip()
            if msg:
                Path(self.bump_file).write_text("")  # consume
                return msg
        except Exception:
            pass
        return None

    def step(self) -> str | None:
        """Execute one ReAct step. Returns observation string or None if finished."""
        if self.done:
            return None

        time_left = self.time_budget_secs - (time.time() - self.time_start)
        if time_left < 60:
            print(f"{YELLOW}[Agent] Time budget exhausted — stopping.{NC}", flush=True)
            self.done = True
            return None

        # ── Check operator bump (guidance injection mid-run) ─────────────
        bump_msg = self._check_bump()
        if bump_msg:
            print(f"{YELLOW}[Agent] BUMP received: {bump_msg}{NC}", flush=True)
            if self.tracer:
                self.tracer.bump(bump_msg, self.memory.step_count)
            self.loop_detector.reset()  # fresh start after guidance
            self.memory.working_memory += f"\n\n[OPERATOR GUIDANCE] {bump_msg}"
            self.memory.save()

        context  = self._build_context()
        user_msg = f"{context}\n\nWhat is the best next action? Call the appropriate tool."

        print(f"\n{CYAN}{'─'*60}{NC}", flush=True)
        print(f"{BOLD}[Agent] Step {self.memory.step_count + 1} — calling LLM...{NC}", flush=True)

        try:
            response = self.client.chat(
                model=self.model,
                messages=[
                    {"role": "system",    "content": AGENT_SYSTEM},
                    {"role": "user",      "content": user_msg},
                ],
                tools=TOOLS,
                options={
                    "num_ctx":     16384,
                    "num_predict": 1024,
                    "temperature": 0.1,
                },
            )
        except Exception as e:
            print(f"{RED}[Agent] LLM call failed: {e}{NC}", flush=True)
            return f"LLM error: {e}"

        msg = response.get("message", {})

        # ── Native tool calling path ─────────────────────────────────────
        tool_calls = msg.get("tool_calls", [])
        if tool_calls:
            results = []
            for tc in tool_calls:
                fn   = tc.get("function", {})
                name = fn.get("name", "")
                args = fn.get("arguments", {})
                if isinstance(args, str):
                    try:
                        args = json.loads(args)
                    except Exception:
                        args = {}

                # ── Persistence enforcement: block early finish ──────────
                if name == "finish" and self.memory.step_count < self.MIN_STEPS_BEFORE_FINISH:
                    remaining_needed = self.MIN_STEPS_BEFORE_FINISH - self.memory.step_count
                    print(f"{YELLOW}[Agent] Finish blocked — only {self.memory.step_count} steps done, "
                          f"need {remaining_needed} more. Continuing...{NC}", flush=True)
                    results.append(
                        f"[SYSTEM] Too early to finish. You have only run "
                        f"{self.memory.step_count} tools. Run at least "
                        f"{remaining_needed} more high-impact tools before concluding."
                    )
                    continue

                # ── Loop detection ───────────────────────────────────────
                warn, must_break = self.loop_detector.record(name, args)
                if must_break:
                    print(f"{RED}[Agent] Loop detected on '{name}' — forcing direction change{NC}",
                          flush=True)
                    if self.tracer:
                        self.tracer.loop_break(name, self.memory.step_count)
                    self.loop_detector.reset()
                    results.append(
                        f"[SYSTEM] Loop detected: '{name}' called 5+ times with identical args. "
                        f"You MUST switch strategy. Try a completely different tool or angle. "
                        f"What have you NOT tried yet?"
                    )
                    continue
                if warn:
                    print(f"{YELLOW}[Agent] Loop warning: '{name}' repeated — consider switching{NC}",
                          flush=True)
                    if self.tracer:
                        self.tracer.loop_warn(name, LoopDetector.WARN_AT, self.memory.step_count)

                print(f"{MAGENTA}[Agent] Tool: {BOLD}{name}{NC}{MAGENTA}  args={json.dumps(args)}{NC}",
                      flush=True)
                if self.tracer:
                    self.tracer.tool_call(name, args, self.memory.step_count)

                t0  = time.time()
                obs = self.dispatcher.dispatch(name, args)
                elapsed = round(time.time() - t0, 1)

                if self.tracer:
                    self.tracer.tool_result(name, obs, elapsed, self.memory.step_count)

                results.append(obs)

                if name == "finish":
                    self.done    = True
                    self.verdict = args.get("verdict", "")
                    if self.tracer:
                        self.tracer.finish(self.verdict, self.memory.step_count,
                                           round((time.time() - self.time_start) / 60, 1))

            return "\n\n---\n\n".join(results)

        # ── Text-based fallback (model didn't use tool calling) ──────────
        content = msg.get("content", "")
        if content:
            print(f"{DIM}[Agent] LLM text response (no tool call):\n{content[:300]}{NC}",
                  flush=True)
            # Try to parse ReAct-format: Action: tool_name / Action Input: {...}
            parsed = self._parse_react_text(content)
            if parsed:
                name, args = parsed
                print(f"{MAGENTA}[Agent] Parsed from text: {name}{NC}", flush=True)
                obs = self.dispatcher.dispatch(name, args)
                if name == "finish":
                    self.done    = True
                    self.verdict = args.get("verdict", "")
                return obs

        # LLM produced nothing useful — nudge it
        self.memory.step_count += 1
        return "(LLM produced no tool call — will retry next step)"

    def _parse_react_text(self, text: str) -> tuple[str, dict] | None:
        """Parse old-style ReAct text format as fallback for non-tool-calling models."""
        import re
        # Match: Action: tool_name\nAction Input: {...}
        m = re.search(
            r"Action:\s*(\w+)\s*\nAction\s+Input:\s*(\{.*?\})",
            text, re.DOTALL
        )
        if m:
            name = m.group(1)
            try:
                args = json.loads(m.group(2))
            except Exception:
                args = {}
            if name in TOOL_NAMES:
                return name, args

        # Simpler: just "Action: tool_name" with no args
        m2 = re.search(r"Action:\s*(\w+)", text)
        if m2:
            name = m2.group(1)
            if name in TOOL_NAMES:
                return name, {}

        return None

    def run(self) -> dict:
        """Run the full ReAct loop until done or max_steps reached."""
        print(f"\n{BOLD}{CYAN}╔══════════════════════════════════════════╗{NC}")
        print(f"{BOLD}{CYAN}║  ReAct Hunt Agent — {self.domain:<20}  ║{NC}")
        print(f"{BOLD}{CYAN}╚══════════════════════════════════════════╝{NC}\n")

        for i in range(self.max_steps):
            if self.done:
                break

            obs = self.step()
            if obs:
                # Print first 500 chars of observation
                preview = obs[:500] + ("..." if len(obs) > 500 else "")
                print(f"{DIM}[Observation]\n{preview}{NC}\n", flush=True)

        if not self.done:
            print(f"{YELLOW}[Agent] Max steps ({self.max_steps}) reached.{NC}", flush=True)

        elapsed = round((time.time() - self.time_start) / 60, 1)
        print(f"\n{GREEN}[Agent] Hunt complete. ({elapsed} min){NC}")
        print(f"  Steps executed:  {self.memory.step_count}")
        print(f"  Completed tools: {', '.join(dict.fromkeys(self.memory.completed_steps))}")
        print(f"  Findings:        {len(self.memory.findings_log)}")
        if self.tracer:
            print(f"  Trace log:       {self.tracer.log_path}")
        if self.bump_file:
            print(f"  Bump file:       {self.bump_file}")
        if self.verdict:
            print(f"  Verdict:         {self.verdict}")

        return {
            "domain":           self.domain,
            "success":          True,
            "model":            self.model,
            "steps":            self.memory.step_count,
            "completed_steps":  list(dict.fromkeys(self.memory.completed_steps)),
            "reports":          len(self.memory.findings_log),
            "findings":         len(self.memory.findings_log),
            "findings_log":     self.memory.findings_log,
            "working_memory":   self.memory.working_memory,
            "verdict":          self.verdict,
            "session_file":     self.memory.session_file,
            # Map completed_steps to phase flags print_dashboard checks
            **{step: (step in self.memory.completed_steps)
               for step in ("recon", "scan", "js_analysis", "secret_hunt",
                            "param_discovery", "api_fuzz", "cors", "cms_exploit",
                            "rce_scan", "sqlmap", "jwt_audit")},
        }


# ──────────────────────────────────────────────────────────────────────────────
#  LangGraph agent  (optional — requires: pip install langgraph langchain-ollama)
# ──────────────────────────────────────────────────────────────────────────────

def build_langgraph_agent(domain: str, dispatcher: ToolDispatcher,
                           memory: HuntMemory, model: str,
                           max_steps: int = 20):
    """
    Build a real LangGraph ReAct agent.
    State: MessagesState (list of messages)
    Nodes: agent (LLM) → tools (ToolNode) → back to agent
    Edges: tools_condition → tool node or END
    """
    if not _LANGGRAPH_OK:
        raise ImportError(
            "LangGraph not installed. Run:\n"
            "  pip install langgraph langchain-ollama\n"
            "Or use the built-in ReAct loop (default, no extra deps)."
        )

    from typing import TypedDict, Annotated
    from langgraph.graph import StateGraph, END
    from langgraph.graph.message import add_messages
    from langgraph.prebuilt import ToolNode, tools_condition
    from langchain_core.messages import HumanMessage, SystemMessage, AIMessage
    from langchain_core.tools import tool as lc_tool, StructuredTool
    import inspect

    # ── Wrap dispatcher calls as LangChain tools ──────────────────────────
    lc_tools = []
    for tool_spec in TOOLS:
        fn_spec = tool_spec["function"]
        tool_name = fn_spec["name"]
        tool_desc = fn_spec["description"]
        props     = fn_spec["parameters"].get("properties", {})

        # Create a closure that captures tool_name
        def _make_tool(tname):
            def _tool_fn(**kwargs):
                return dispatcher.dispatch(tname, kwargs)
            _tool_fn.__name__ = tname
            _tool_fn.__doc__  = tool_desc
            return lc_tool(_tool_fn)

        lc_tools.append(_make_tool(tool_name))

    # ── LLM with tools bound ──────────────────────────────────────────────
    llm = ChatOllama(
        model=model,
        base_url=OLLAMA_HOST,
        temperature=0.1,
        num_ctx=16384,
    )
    llm_with_tools = llm.bind_tools(lc_tools)

    # ── State ──────────────────────────────────────────────────────────────
    class HuntState(TypedDict):
        messages: Annotated[list, add_messages]

    # ── Graph nodes ────────────────────────────────────────────────────────
    def agent_node(state: HuntState) -> HuntState:
        context = f"Target: {domain}\n\n" + _build_context_for_langgraph(domain, memory)
        # Prepend system + context to messages if first call
        msgs = state["messages"]
        if not any(isinstance(m, SystemMessage) for m in msgs):
            msgs = [SystemMessage(content=AGENT_SYSTEM),
                    HumanMessage(content=context)] + list(msgs)
        response = llm_with_tools.invoke(msgs)
        # Check finish signal
        if hasattr(response, "tool_calls"):
            for tc in (response.tool_calls or []):
                if tc.get("name") == "finish":
                    memory.working_memory += f"\n\nFINISHED: {tc.get('args', {}).get('verdict', '')}"
        return {"messages": [response]}

    tool_node = ToolNode(lc_tools)

    def should_continue(state: HuntState):
        last = state["messages"][-1]
        if not hasattr(last, "tool_calls") or not last.tool_calls:
            return END
        if any(tc.get("name") == "finish" for tc in last.tool_calls):
            return END
        if memory.step_count >= max_steps:
            return END
        return "tools"

    # ── Build graph ────────────────────────────────────────────────────────
    graph = StateGraph(HuntState)
    graph.add_node("agent", agent_node)
    graph.add_node("tools", tool_node)
    graph.set_entry_point("agent")
    graph.add_conditional_edges("agent", should_continue, {"tools": "tools", END: END})
    graph.add_edge("tools", "agent")

    return graph.compile()


def _build_context_for_langgraph(domain: str, memory: HuntMemory) -> str:
    """Same context builder used by LangGraph agent node."""
    completed = list(dict.fromkeys(memory.completed_steps))
    return (
        f"Completed steps: {', '.join(completed) or 'none'}\n"
        f"Working memory:\n{memory.working_memory or '(empty)'}\n\n"
        f"Findings so far:\n{memory.findings_summary()}\n\n"
        f"Recent observations:\n{memory.recent_observations(2)}"
    )


# ──────────────────────────────────────────────────────────────────────────────
#  Public entry point  (called by hunt.py --agent)
# ──────────────────────────────────────────────────────────────────────────────

def run_agent_hunt(
    domain: str,
    *,
    scope_lock: bool = False,
    max_urls: int = 100,
    max_steps: int = 20,
    time_budget_hours: float = 2.0,
    cookies: str = "",
    model: str | None = None,
    resume_session_id: str | None = None,
    use_langgraph: bool = False,
) -> dict:
    """
    Main entry point for agent-driven autonomous hunting.
    Called by hunt.py when --agent flag is passed.
    """
    h = _h()

    # ── Resolve session ───────────────────────────────────────────────────
    session_id, recon_dir = h._activate_recon_session(
        domain,
        requested_session_id=resume_session_id or "latest",
        create=True,
    )
    session_dir  = os.path.dirname(recon_dir)
    session_file = os.path.join(session_dir, "agent_session.json")

    print(f"{GREEN}[Agent] Session: {session_id} → {recon_dir}{NC}", flush=True)

    # ── Init memory + dispatcher ──────────────────────────────────────────
    memory     = HuntMemory(session_file)
    dispatcher = ToolDispatcher(
        domain, memory,
        scope_lock=scope_lock,
        max_urls=max_urls,
        default_cookies=cookies,
    )

    # ── Run ───────────────────────────────────────────────────────────────
    if use_langgraph and _LANGGRAPH_OK:
        print(f"{GREEN}[Agent] Using real LangGraph backend.{NC}", flush=True)
        picked_model = model or (_pick_model() if _BRAIN_OK else None) or "qwen2.5:32b"
        try:
            graph   = build_langgraph_agent(domain, dispatcher, memory, picked_model, max_steps)
            initial = {"messages": [HumanMessage(content=f"Hunt {domain}. Begin.")]}
            result_state = graph.invoke(initial, config={"recursion_limit": max_steps * 2})
            return {
                "domain":          domain,
                "success":         True,
                "model":           picked_model,
                "backend":         "langgraph",
                "steps":           memory.step_count,
                "completed_steps": list(dict.fromkeys(memory.completed_steps)),
                "reports":         len(memory.findings_log),
                "findings":        len(memory.findings_log),
                "session_file":    session_file,
                "working_memory":  memory.working_memory,
                **{step: (step in memory.completed_steps)
                   for step in ("recon", "scan", "js_analysis", "secret_hunt",
                                "param_discovery", "api_fuzz", "cors", "cms_exploit",
                                "rce_scan", "sqlmap", "jwt_audit")},
            }
        except Exception as e:
            print(f"{YELLOW}[Agent] LangGraph error: {e} — falling back to built-in{NC}",
                  flush=True)

    # Built-in ReAct loop
    log_path  = os.path.join(session_dir, "agent_trace.jsonl")
    bump_path = os.path.join(session_dir, "agent_bump.txt")
    tracer    = AgentTracer(log_path)

    print(f"{GREEN}[Agent] Trace: tail -f {log_path}{NC}", flush=True)
    print(f"{GREEN}[Agent] Bump:  echo 'guidance here' > {bump_path}{NC}", flush=True)

    agent = ReActAgent(
        domain      = domain,
        memory      = memory,
        dispatcher  = dispatcher,
        max_steps   = max_steps,
        time_budget_hours = time_budget_hours,
        model       = model,
        tracer      = tracer,
    )
    agent.bump_file = bump_path

    result = agent.run()
    tracer.close()
    result["backend"]    = "builtin-react"
    result["trace_path"] = log_path
    result["bump_path"]  = bump_path
    return result


# ──────────────────────────────────────────────────────────────────────────────
#  CLI
# ──────────────────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(
        description="ReAct hunting agent — autonomous bug bounty with Ollama tool calling",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 agent.py --target example.com
  python3 agent.py --target example.com --time 4 --max-steps 30
  python3 agent.py --target example.com --cookie "JSESSIONID=abc123"
  python3 agent.py --target example.com --scope-lock --max-urls 50
  python3 agent.py --target example.com --langgraph
  python3 agent.py --target example.com --resume SESSION_ID
  python3 agent.py --list-models
"""
    )
    parser.add_argument("--target",      required=False, help="Domain to hunt")
    parser.add_argument("--time",        type=float, default=2.0, help="Time budget in hours (default 2)")
    parser.add_argument("--max-steps",   type=int,   default=20,  help="Max ReAct iterations (default 20)")
    parser.add_argument("--cookie",      type=str,   default="",  help="Session cookie for POST discovery")
    parser.add_argument("--scope-lock",  action="store_true",     help="Stick to exact target only")
    parser.add_argument("--max-urls",    type=int,   default=100, help="Max URLs in recon (default 100)")
    parser.add_argument("--model",       type=str,   default=None, help="Ollama model override")
    parser.add_argument("--langgraph",   action="store_true",     help="Use real LangGraph backend")
    parser.add_argument("--resume",      type=str,   default=None, help="Resume session ID")
    parser.add_argument("--list-models", action="store_true",     help="List available Ollama models")
    parser.add_argument("--bump",        type=str,   default=None,
                        help="Inject operator guidance mid-run: --bump SESSION_DIR 'message'",
                        nargs=2, metavar=("SESSION_DIR", "MESSAGE"))
    args = parser.parse_args()

    if args.list_models:
        if not _OLLAMA_OK:
            print("Ollama not installed: pip install ollama")
            return
        client = _ollama_lib.Client(host=OLLAMA_HOST)
        try:
            models = [m.model for m in client.list().models]
            print(f"\nAvailable Ollama models ({len(models)}):")
            for m in models:
                marker = " ← recommended" if any(m.startswith(p.split(":")[0]) for p in
                         ["qwen3-coder", "qwen2.5", "qwen3"]) else ""
                print(f"  {m}{marker}")
        except Exception as e:
            print(f"Cannot reach Ollama: {e}")
        print(f"\nLangGraph available: {_LANGGRAPH_OK}")
        print(f"Ollama available:    {_OLLAMA_OK}")
        return

    if args.bump:
        session_dir, message = args.bump
        bump_file = os.path.join(session_dir, "agent_bump.txt")
        Path(bump_file).write_text(message.strip())
        print(f"[Bump] Wrote guidance to {bump_file}")
        print(f"[Bump] Agent will pick it up on next step.")
        return

    if not args.target:
        parser.print_help()
        sys.exit(1)

    result = run_agent_hunt(
        args.target,
        scope_lock=args.scope_lock,
        max_urls=args.max_urls,
        max_steps=args.max_steps,
        time_budget_hours=args.time,
        cookies=args.cookie,
        model=args.model,
        resume_session_id=args.resume,
        use_langgraph=args.langgraph,
    )

    print(f"\n{BOLD}{'═'*60}{NC}")
    print(f"{BOLD}Hunt Result: {result['domain']}{NC}")
    print(f"  Backend:   {result.get('backend', 'unknown')}")
    print(f"  Model:     {result.get('model', 'unknown')}")
    print(f"  Steps:     {result.get('steps', 0)}")
    print(f"  Findings:  {result.get('findings', 0)}")
    print(f"  Session:   {result.get('session_file', '')}")
    if result.get("trace_path"):
        print(f"  Trace:     {result['trace_path']}")
    if result.get("bump_path"):
        print(f"  Bump:      echo 'guidance' > {result['bump_path']}")
    if result.get("verdict"):
        print(f"\nVerdict:\n{result['verdict']}")
    print(f"{BOLD}{'═'*60}{NC}\n")


if __name__ == "__main__":
    main()
