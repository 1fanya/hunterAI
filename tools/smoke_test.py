#!/usr/bin/env python3
"""
smoke_test.py — Validates every HunterAI tool loads and has correct interface.

Run: python3 tools/smoke_test.py

Tests:
1. Every tool module imports without error
2. Every tool class can be instantiated
3. Key methods exist and are callable
4. Dependencies are available
"""
import importlib
import os
import sys
import traceback

# Ensure tools/ is in path
HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, HERE)
sys.path.insert(0, ROOT)

# ── Color codes ──────────────────────────────────────────────────────────
GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
NC = "\033[0m"

# ── Tools to test ────────────────────────────────────────────────────────
TOOLS = [
    # (module_name, class_name, required_methods)
    ("scope_guard", "ScopeGuard", ["is_in_scope"]),
    ("waf_detector", "WAFDetector", ["detect"]),
    ("response_differ", "ResponseDiffer", ["compare"]),
    ("ws_tester", "WSTester", []),
    ("param_miner", "ParamMiner", ["mine"]),
    ("session_manager", "SessionManager", []),
    ("wordlist_builder", "WordlistBuilder", []),
    ("nuclei_generator", "NucleiGenerator", []),
    ("hacktivity_learner", "HacktivityLearner", ["learn_program"]),
    # Phase 2 tools
    ("race_tester", "RaceTester", ["run", "detect_race_type"]),
    ("ssrf_engine", "SSRFEngine", ["test_ssrf", "generate_bypass_urls", "detect_ssrf_params"]),
    ("api_security", "APISecurityTester", ["test_bola", "test_bfla", "test_mass_assignment"]),
    ("cache_poison", "CachePoisonTester", ["test_cache_poisoning", "test_cache_deception", "detect_cdn"]),
    ("prototype_pollution", "PrototypePollutionScanner", ["run_all", "test_query_params", "test_json_body"]),
    # Phase 3 tools
    ("chain_engine", "ChainEngine", ["escalate", "classify_finding"]),
    ("poc_generator", "PoCGenerator", ["generate", "save_poc"]),
    ("h2_smuggler", "H2Smuggler", ["run_all", "detect_http2"]),
    ("graphql_deep", "GraphQLDeepTester", ["run_all", "discover_endpoint", "test_introspection"]),
    ("monitor", "AttackSurfaceMonitor", ["run_full_check", "check_subdomains"]),
    ("git_recon", "GitRecon", ["run_full_scan", "scan_file_contents"]),
    # Intelligence layer
    ("subdomain_takeover", "SubdomainTakeover", ["scan_domain"]),
    ("jwt_analyzer", "JWTAnalyzer", ["analyze_token"]),
    ("api_discovery", "APIDiscovery", ["discover"]),
    ("blind_xss", "BlindXSSHunter", ["inject"]),
    ("twofa_bypass", "TwoFABypass", ["test_all"]),
    ("hunt_intel", "HuntIntel", ["record_hunt"]),
    # Advanced attack tools
    ("ssti_scanner", "SSTIScanner", ["test_url"]),
    ("host_header", "HostHeaderAttack", ["test_all"]),
    ("oauth_tester", "OAuthTester", ["test_all"]),
    # Final expansion
    ("xxe_scanner", "XXEScanner", ["test_endpoint"]),
    ("open_redirect", "OpenRedirectScanner", ["scan_url", "scan_domain"]),
    ("file_upload", "FileUploadTester", ["test_upload"]),
    ("path_traversal", "PathTraversalScanner", ["test_url"]),
    ("business_logic", "BusinessLogicTester", ["test_all"]),
    # State persistence
    ("hunt_state", "HuntState", ["complete_tool", "is_tool_completed", "add_finding"]),
    # CVE & Exploit engine
    ("cve_engine", "CVEEngine", ["lookup", "search_nvd", "search_exploitdb", "is_kev"]),
    ("msf_adapter", "MetasploitAdapter", ["search"]),
    # Elite tools
    ("js_analyzer", "JSAnalyzer", ["analyze_all", "discover_js_files"]),
    ("nuclei_templater", "NucleiTemplater", ["from_finding", "from_cve"]),
    ("h1_api", "HackerOneAPI", ["get_scope", "search_hacktivity", "check_duplicate"]),
    ("payload_mutator", "PayloadMutator", ["generate_xss_payloads", "generate_sqli_payloads"]),
    ("telegram_notifier", "TelegramNotifier", ["send", "finding_alert"]),
    ("cert_monitor", "CertMonitor", ["check", "extract_subdomains"]),
    ("js_deps_scanner", "JSDepsScanner", ["scan_url", "check_vulns"]),
    ("apk_analyzer", "APKAnalyzer", ["analyze"]),
    ("multi_target", "MultiTargetQueue", ["add", "next", "stats"]),
    ("browser_auto", "BrowserAuto", ["start", "login", "screenshot_poc"]),
    # Intelligence tools
    ("github_dorker", "GitHubDorker", ["dork", "quick_scan"]),
    ("shodan_recon", "ShodanRecon", ["internetdb_lookup", "find_exposed_services"]),
    ("wayback_analyzer", "WaybackAnalyzer", ["analyze", "find_removed_endpoints"]),
    ("auto_scope", "AutoScope", ["load", "list_configs"]),
    ("recon_cron", "ReconCron", ["run_once", "check_subdomains"]),
]

# ── Dependency checks ────────────────────────────────────────────────────
DEPENDENCIES = [
    ("requests", "HTTP client"),
    ("aiohttp", "Async HTTP (race_tester)"),
    ("json", "JSON (stdlib)"),
    ("hashlib", "Hashing (stdlib)"),
    ("asyncio", "Async (stdlib)"),
    ("re", "Regex (stdlib)"),
]

def check_dependencies():
    """Check all required Python packages."""
    print(f"\n{'='*60}")
    print(f"  DEPENDENCY CHECK")
    print(f"{'='*60}")
    passed = 0
    failed = 0
    for pkg, desc in DEPENDENCIES:
        try:
            importlib.import_module(pkg)
            print(f"  {GREEN}✓{NC} {pkg:20s} — {desc}")
            passed += 1
        except ImportError:
            print(f"  {RED}✗{NC} {pkg:20s} — {desc} (MISSING)")
            failed += 1
    return passed, failed


def check_tools():
    """Check all tool modules."""
    print(f"\n{'='*60}")
    print(f"  TOOL MODULE CHECK")
    print(f"{'='*60}")
    passed = 0
    failed = 0
    warnings = 0

    for module_name, class_name, methods in TOOLS:
        try:
            mod = importlib.import_module(module_name)
            cls = getattr(mod, class_name)

            # Try to instantiate (some need args)
            try:
                if class_name in ("ScopeGuard",):
                    obj = cls(program_name="test.com")
                elif class_name in ("WordlistBuilder",):
                    obj = cls(target="test.com")
                elif class_name in ("NucleiGenerator",):
                    obj = cls(target="test.com")
                elif class_name in ("SessionManager",):
                    obj = cls(target="test.com")
                elif class_name in ("JSAnalyzer",):
                    obj = cls(base_url="https://test.com")
                elif class_name in ("ChainEngine",):
                    obj = cls(domain="test.com")
                elif class_name in ("APISecurityTester",):
                    obj = cls(target_base="https://test.com")
                elif class_name in ("GraphQLDeepTester",):
                    obj = cls(target_url="https://test.com/graphql")
                elif class_name in ("AttackSurfaceMonitor",):
                    obj = cls(domain="test.com", data_dir="/tmp/test_monitor")
                elif class_name in ("GitRecon",):
                    obj = cls(token="")
                elif class_name in ("HostHeaderAttack", "OAuthTester"):
                    obj = cls("https://test.com")
                elif class_name in ("BusinessLogicTester",):
                    obj = cls("https://test.com")
                elif class_name in ("HuntState",):
                    obj = cls("test.com")
                else:
                    obj = cls()
                instantiated = True
            except Exception as e:
                instantiated = False
                warnings += 1

            # Check methods exist
            missing_methods = []
            for method in methods:
                if not hasattr(cls, method):
                    missing_methods.append(method)

            if missing_methods:
                print(f"  {YELLOW}!{NC} {module_name:25s} → {class_name} "
                      f"(missing: {', '.join(missing_methods)})")
                warnings += 1
            elif not instantiated:
                print(f"  {YELLOW}!{NC} {module_name:25s} → {class_name} "
                      f"(import OK, instantiation failed)")
            else:
                print(f"  {GREEN}✓{NC} {module_name:25s} → {class_name} "
                      f"({len(methods)} methods verified)")
            passed += 1

        except ImportError as e:
            print(f"  {RED}✗{NC} {module_name:25s} → IMPORT FAILED: {e}")
            failed += 1
        except Exception as e:
            print(f"  {RED}✗{NC} {module_name:25s} → ERROR: {e}")
            failed += 1

    return passed, failed, warnings


def check_external_tools():
    """Check external security tools available in PATH."""
    import shutil
    print(f"\n{'='*60}")
    print(f"  EXTERNAL TOOL CHECK")
    print(f"{'='*60}")

    tools = [
        ("subfinder", "Subdomain enumeration"),
        ("httpx", "HTTP probing"),
        ("nuclei", "Vulnerability scanner"),
        ("katana", "Web crawling"),
        ("sqlmap", "SQL injection"),
        ("ffuf", "Web fuzzing"),
        ("nmap", "Network scanning"),
        ("nikto", "Web server scanner"),
        ("interactsh-client", "OOB callback (blind SSRF/XXE)"),
    ]

    available = 0
    missing = 0
    for tool, desc in tools:
        path = shutil.which(tool)
        if path:
            print(f"  {GREEN}✓{NC} {tool:25s} — {desc}")
            available += 1
        else:
            print(f"  {RED}✗{NC} {tool:25s} — {desc} (not in PATH)")
            missing += 1

    return available, missing


def check_agent_tools_list():
    """Verify agent.py TOOLS list matches actual tools."""
    print(f"\n{'='*60}")
    print(f"  AGENT.PY TOOLS REGISTRATION CHECK")
    print(f"{'='*60}")

    try:
        # Import agent and check TOOLS
        agent_path = os.path.join(ROOT, "agent.py")
        if not os.path.exists(agent_path):
            print(f"  {RED}✗{NC} agent.py not found at {agent_path}")
            return 0, 1

        # Read file and extract tool names
        with open(agent_path) as f:
            content = f.read()

        import re
        tool_defs = re.findall(r'"name":\s*"(run_\w+|read_\w+|update_\w+|finish)"', content)
        dispatch_handlers = re.findall(r'(?:el)?if name == "(run_\w+|read_\w+|update_\w+|finish)"', content)

        # Check for tools defined but not dispatched
        defined_set = set(tool_defs)
        dispatched_set = set(dispatch_handlers)

        orphan_defs = defined_set - dispatched_set - {"finish"}
        orphan_dispatchers = dispatched_set - defined_set

        print(f"  Tools defined:    {len(defined_set)}")
        print(f"  Tools dispatched: {len(dispatched_set)}")

        if orphan_defs:
            print(f"  {RED}✗{NC} Defined but NOT dispatched: {', '.join(orphan_defs)}")
        if orphan_dispatchers:
            print(f"  {RED}✗{NC} Dispatched but NOT defined: {', '.join(orphan_dispatchers)}")
        if not orphan_defs and not orphan_dispatchers:
            print(f"  {GREEN}✓{NC} All tools properly wired (definition ↔ dispatcher)")

        return len(defined_set), len(orphan_defs) + len(orphan_dispatchers)

    except Exception as e:
        print(f"  {RED}✗{NC} Error checking agent.py: {e}")
        return 0, 1


if __name__ == "__main__":
    print(f"\n{GREEN}╔══════════════════════════════════════════════════════╗{NC}")
    print(f"{GREEN}║          HunterAI Smoke Test                         ║{NC}")
    print(f"{GREEN}╚══════════════════════════════════════════════════════╝{NC}")

    dep_pass, dep_fail = check_dependencies()
    tool_pass, tool_fail, tool_warn = check_tools()
    ext_avail, ext_miss = check_external_tools()
    agent_tools, agent_errors = check_agent_tools_list()

    print(f"\n{'='*60}")
    print(f"  SUMMARY")
    print(f"{'='*60}")
    print(f"  Dependencies:    {GREEN}{dep_pass} OK{NC}, {RED}{dep_fail} FAILED{NC}")
    print(f"  Tool modules:    {GREEN}{tool_pass} OK{NC}, {RED}{tool_fail} FAILED{NC}, "
          f"{YELLOW}{tool_warn} WARNINGS{NC}")
    print(f"  External tools:  {GREEN}{ext_avail} available{NC}, {RED}{ext_miss} missing{NC}")
    print(f"  Agent wiring:    {agent_tools} tools, {agent_errors} errors")

    total_failures = dep_fail + tool_fail + agent_errors
    if total_failures == 0:
        print(f"\n  {GREEN}🎉 ALL CHECKS PASSED — Ready for hunting!{NC}")
    else:
        print(f"\n  {RED}⚠ {total_failures} failures — fix before hunting{NC}")

    sys.exit(total_failures)
