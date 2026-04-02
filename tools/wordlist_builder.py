#!/usr/bin/env python3
"""
Wordlist Builder — Generate target-specific wordlists from recon data.

Extracts words from JS bundles, URLs, subdomains, and HTML.
Downloads SecLists subsets for comprehensive coverage.

Usage:
    python3 wordlist_builder.py --target target.com --recon-dir recon/target.com
    python3 wordlist_builder.py --install-seclists
"""

import argparse
import json
import os
import re
import subprocess
import sys
from urllib.parse import urlparse, parse_qs

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
WORDLIST_DIR = os.path.join(BASE_DIR, "wordlists")

GREEN = "\033[0;32m"
RED = "\033[0;31m"
YELLOW = "\033[1;33m"
CYAN = "\033[0;36m"
BOLD = "\033[1m"
NC = "\033[0m"

def log(level, msg):
    colors = {"ok": GREEN, "err": RED, "warn": YELLOW, "info": CYAN}
    symbols = {"ok": "+", "err": "-", "warn": "!", "info": "*"}
    print(f"{colors.get(level, '')}{BOLD}[{symbols.get(level, '*')}]{NC} {msg}")

FRAMEWORK_PATHS = {
    "laravel": ["telescope","horizon",".env","api/user","oauth/token","storage/logs/laravel.log"],
    "django": ["admin","__debug__","api-auth","graphql","rest-auth","static","media"],
    "express": ["graphql","api-docs","swagger.json","health","metrics",".env"],
    "rails": ["rails/info","sidekiq","admin","cable","graphql"],
    "spring": ["actuator","actuator/env","actuator/heapdump","actuator/health","actuator/mappings",
               "swagger-ui.html","v2/api-docs","v3/api-docs","h2-console","jolokia"],
    "wordpress": ["wp-json/wp/v2/users","wp-admin","wp-login.php","xmlrpc.php",
                  "wp-content/uploads","wp-config.php.bak"],
    "nextjs": ["_next/data","_next/static","api","__nextjs_original-stack-frame"],
    "graphql": ["graphql","graphiql","playground","altair","graphql/schema.json"],
}

SECLISTS_URLS = {
    "dirs-common.txt": "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/common.txt",
    "dirs-medium.txt": "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/directory-list-2.3-medium.txt",
    "params-burp.txt": "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/burp-parameter-names.txt",
    "api-endpoints.txt": "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/api/api-endpoints.txt",
    "raft-large-dirs.txt": "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/raft-large-directories.txt",
    "sensitive-files.txt": "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/quickhits.txt",
    "subdomains-top5000.txt": "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/subdomains-top1million-5000.txt",
    "sqli-payloads.txt": "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Fuzzing/SQLi/Generic-SQLi.txt",
    "xss-payloads.txt": "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Fuzzing/XSS/XSS-Jhaddix.txt",
    "lfi-payloads.txt": "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Fuzzing/LFI/LFI-Jhaddix.txt",
}


class WordlistBuilder:
    def __init__(self, target, recon_dir=None):
        self.target = target
        self.recon_dir = recon_dir or os.path.join(BASE_DIR, "recon", target)
        self.output_dir = os.path.join(WORDLIST_DIR, "generated", target)
        os.makedirs(self.output_dir, exist_ok=True)

    def _read_lines(self, path):
        if not os.path.exists(path): return []
        try:
            with open(path, errors="replace") as f:
                return [l.strip() for l in f if l.strip()]
        except IOError: return []

    def _save(self, name, words):
        with open(os.path.join(self.output_dir, name), "w") as f:
            f.write("\n".join(words) + "\n")

    def extract_from_urls(self, urls):
        paths, params = set(), set()
        for url in urls:
            try:
                p = urlparse(url)
                for seg in p.path.split("/"):
                    if seg and not re.match(r'^\d+$', seg): paths.add(seg)
                for key in parse_qs(p.query): params.add(key)
            except: continue
        return sorted(paths), sorted(params)

    def extract_from_js(self):
        endpoints = set()
        js_dir = os.path.join(self.recon_dir, "js")
        if not os.path.isdir(js_dir): return []
        for fname in os.listdir(js_dir):
            try:
                with open(os.path.join(js_dir, fname), errors="replace") as f:
                    content = f.read()
                for m in re.finditer(r'["\'](/[a-zA-Z0-9_/\-\.]+)["\']', content):
                    path = m.group(1)
                    if len(path) > 1: endpoints.add(path)
                    for seg in path.split("/"):
                        if seg and not re.match(r'^\d+$', seg): endpoints.add(seg)
            except: continue
        return sorted(endpoints)[:2000]

    def extract_from_subdomains(self):
        prefixes = set()
        for f in ("subdomains/all.txt", "subdomains.txt"):
            for sub in self._read_lines(os.path.join(self.recon_dir, f)):
                for part in sub.replace(f".{self.target}", "").split("."):
                    if part and part != self.target and len(part) > 1: prefixes.add(part)
        return sorted(prefixes)

    def get_framework_paths(self, tech_stack=None):
        paths = set()
        if not tech_stack:
            pf = os.path.join(self.recon_dir, "tech_profile.json")
            if os.path.exists(pf):
                try:
                    with open(pf) as f: tech_stack = json.load(f).get("technologies", [])
                except: tech_stack = []
        for tech in (tech_stack or []):
            for fw, fw_paths in FRAMEWORK_PATHS.items():
                if fw in tech.lower(): paths.update(fw_paths)
        return sorted(paths)

    def build_all(self, tech_stack=None):
        log("info", f"Building wordlists for {self.target}")
        results = {}
        urls = []
        for f in ("urls/all.txt", "urls/urls.txt", "urls.txt"):
            urls.extend(self._read_lines(os.path.join(self.recon_dir, f)))
        if urls:
            paths, params = self.extract_from_urls(urls)
            self._save("dirs-target.txt", paths); self._save("params-target.txt", params)
            results["paths"] = len(paths); results["params"] = len(params)
            log("ok", f"URLs: {len(paths)} paths, {len(params)} params")
        js_eps = self.extract_from_js()
        if js_eps:
            self._save("endpoints-js.txt", js_eps); results["js_endpoints"] = len(js_eps)
            log("ok", f"JS: {len(js_eps)} endpoints")
        sub_pf = self.extract_from_subdomains()
        if sub_pf:
            self._save("subdomain-prefixes.txt", sub_pf); results["sub_prefixes"] = len(sub_pf)
        fw = self.get_framework_paths(tech_stack)
        if fw: self._save("framework-paths.txt", fw); results["fw_paths"] = len(fw)
        all_w = set()
        for f in os.listdir(self.output_dir):
            all_w.update(self._read_lines(os.path.join(self.output_dir, f)))
        self._save("master.txt", sorted(all_w))
        results["total"] = len(all_w)
        log("ok", f"Master: {len(all_w)} entries → {self.output_dir}/master.txt")
        return results

    @staticmethod
    def install_seclists():
        dest = os.path.join(WORDLIST_DIR, "seclists")
        os.makedirs(dest, exist_ok=True)
        log("info", f"Downloading SecLists subsets to {dest}")
        for name, url in SECLISTS_URLS.items():
            fp = os.path.join(dest, name)
            if os.path.exists(fp) and os.path.getsize(fp) > 100:
                log("ok", f"Exists: {name}"); continue
            log("info", f"Downloading: {name}")
            try:
                subprocess.run(["curl","-sL",url,"-o",fp], timeout=120, capture_output=True)
                if os.path.exists(fp) and os.path.getsize(fp) > 100:
                    log("ok", f"OK: {name} ({sum(1 for _ in open(fp))} lines)")
                else: log("err", f"Failed: {name}")
            except Exception as e: log("err", f"Error: {name}: {e}")
        log("ok", "SecLists subsets ready")

def main():
    p = argparse.ArgumentParser(description="Target-Specific Wordlist Builder")
    p.add_argument("--target", help="Target domain")
    p.add_argument("--recon-dir", help="Recon data directory")
    p.add_argument("--install-seclists", action="store_true")
    p.add_argument("--tech", nargs="*", help="Tech stack hints")
    args = p.parse_args()
    if args.install_seclists: WordlistBuilder.install_seclists(); return
    if not args.target: p.error("--target required")
    b = WordlistBuilder(args.target, args.recon_dir)
    print(json.dumps(b.build_all(args.tech), indent=2))

if __name__ == "__main__": main()
