#!/usr/bin/env python3
"""
Recon Adapter — Normalize recon output from different sources into canonical format.

Resolves TODO-5: recon_engine.sh outputs nested dirs while recon-agent.md expects flat.
This adapter reads any format and outputs the canonical structure.

Usage:
    python3 recon_adapter.py --recon-dir recon/target.com --normalize
"""

import argparse
import json
import os
import sys

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

GREEN = "\033[0;32m"
YELLOW = "\033[1;33m"
CYAN = "\033[0;36m"
BOLD = "\033[1m"
NC = "\033[0m"

def log(level, msg):
    colors = {"ok": GREEN, "warn": YELLOW, "info": CYAN}
    symbols = {"ok": "+", "warn": "!", "info": "*"}
    print(f"{colors.get(level, '')}{BOLD}[{symbols.get(level, '*')}]{NC} {msg}")


# Canonical output structure expected by the agent
CANONICAL = {
    "subdomains": "subdomains.txt",    # flat list
    "live_hosts": "live-hosts.txt",     # httpx output with status/title/tech
    "urls": "urls.txt",                 # all crawled URLs
    "api_endpoints": "api-endpoints.txt",
    "params": "params.txt",              # URLs with parameters
    "js_endpoints": "js-endpoints.txt",
    "nuclei": "nuclei.txt",
    "secrets": "secrets.txt",
}


def normalize(recon_dir: str) -> dict:
    """Normalize recon directory to canonical format.

    Creates symlinks/copies from nested structure to flat files.
    """
    stats = {}

    # Map: nested path → canonical name
    mappings = [
        ("subdomains/all.txt", "subdomains.txt"),
        ("live/httpx_full.txt", "live-hosts.txt"),
        ("live/urls.txt", "live-urls.txt"),
        ("urls/all.txt", "urls.txt"),
        ("urls/api_endpoints.txt", "api-endpoints.txt"),
        ("urls/with_params.txt", "params.txt"),
        ("js/endpoints.txt", "js-endpoints.txt"),
        ("js/potential_secrets.txt", "secrets.txt"),
        ("params/unique_params.txt", "unique-params.txt"),
        ("params/interesting_params.txt", "interesting-params.txt"),
        ("exposure/config_files.txt", "exposed-configs.txt"),
    ]

    for nested, canonical in mappings:
        src = os.path.join(recon_dir, nested)
        dst = os.path.join(recon_dir, canonical)

        if os.path.exists(src) and not os.path.exists(dst):
            # Create symlink (or copy on Windows)
            try:
                os.symlink(src, dst)
            except (OSError, NotImplementedError):
                import shutil
                shutil.copy2(src, dst)

            lines = sum(1 for _ in open(src))
            stats[canonical] = lines
            log("ok", f"  {canonical} → {lines} entries")

        elif os.path.exists(dst):
            lines = sum(1 for _ in open(dst))
            stats[canonical] = lines

    # Also check for flat-format recon (from recon-agent.md)
    for canon_name in CANONICAL.values():
        path = os.path.join(recon_dir, canon_name)
        if os.path.exists(path) and canon_name not in stats:
            lines = sum(1 for _ in open(path))
            stats[canon_name] = lines

    # Generate summary
    summary_file = os.path.join(recon_dir, "recon_summary.json")
    summary = {
        "target": os.path.basename(recon_dir),
        "files": stats,
        "total_items": sum(stats.values()),
        "normalized_at": __import__("datetime").datetime.now(
            __import__("datetime").timezone.utc).isoformat(),
    }
    with open(summary_file, "w") as f:
        json.dump(summary, f, indent=2)

    log("ok", f"Normalized {len(stats)} files, {sum(stats.values())} total items")
    return stats


def get_recon_data(recon_dir: str) -> dict:
    """Read normalized recon data into a structured dict for agent consumption."""
    data = {}

    for key, filename in CANONICAL.items():
        path = os.path.join(recon_dir, filename)
        if os.path.exists(path):
            with open(path, errors="replace") as f:
                data[key] = [l.strip() for l in f if l.strip()]
        else:
            data[key] = []

    return data


def main():
    p = argparse.ArgumentParser(description="Recon Output Normalizer")
    p.add_argument("--recon-dir", required=True, help="Recon data directory")
    p.add_argument("--normalize", action="store_true", help="Normalize to canonical format")
    p.add_argument("--summary", action="store_true", help="Print summary")
    args = p.parse_args()

    if args.normalize:
        normalize(args.recon_dir)
    elif args.summary:
        data = get_recon_data(args.recon_dir)
        for key, items in data.items():
            print(f"  {key}: {len(items)} items")
    else:
        normalize(args.recon_dir)

if __name__ == "__main__":
    main()
