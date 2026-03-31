#!/usr/bin/env python3
"""
Multi-Model Cost Router for Bug Bounty Hunting

Routes tasks to the appropriate Claude model based on:
- Task complexity (recon=cheap, hunting=mid, reporting=premium)
- Cost mode (cheap/balanced/quality)
- Effort setting (low/medium/high/max)
- Pro subscription awareness

Usage:
    from model_router import ModelRouter
    router = ModelRouter(cost_mode="balanced")
    model = router.get_model("hunting")
    effort = router.get_effort("hunting")
"""

import json
import os
from datetime import datetime

CONFIG_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "config.json")

# Model definitions with relative cost tiers
MODELS = {
    "haiku": {
        "id": "claude-haiku-4-5-20251001",
        "tier": "cheap",
        "cost_per_1k_input": 0.0008,
        "cost_per_1k_output": 0.004,
        "strengths": ["fast", "classification", "extraction", "simple-reasoning"],
    },
    "sonnet": {
        "id": "claude-sonnet-4-6",
        "tier": "mid",
        "cost_per_1k_input": 0.003,
        "cost_per_1k_output": 0.015,
        "strengths": ["reasoning", "code-analysis", "exploitation", "validation"],
    },
    "opus": {
        "id": "claude-opus-4-6",
        "tier": "premium",
        "cost_per_1k_input": 0.015,
        "cost_per_1k_output": 0.075,
        "strengths": ["writing", "complex-analysis", "report-quality", "nuance"],
    },
}

# Default task-to-model routing
DEFAULT_ROUTING = {
    # Cheap tier — fast, simple, high-volume tasks
    "recon": "haiku",
    "subdomain_enum": "haiku",
    "live_host_check": "haiku",
    "url_crawl": "haiku",
    "scope_import": "haiku",
    "ranking": "haiku",
    "dedup_check": "haiku",
    "tech_fingerprint": "haiku",
    "js_analysis": "haiku",

    # Mid tier — reasoning + exploitation
    "hunting": "sonnet",
    "idor_testing": "sonnet",
    "auth_bypass": "sonnet",
    "ssrf_testing": "sonnet",
    "race_condition": "sonnet",
    "business_logic": "sonnet",
    "chain_building": "sonnet",
    "validation": "sonnet",
    "exploit_verification": "sonnet",
    "orchestration": "sonnet",
    "vuln_analysis": "sonnet",

    # Premium tier — quality-critical
    "report_writing": "opus",
    "complex_analysis": "opus",
    "severity_assessment": "opus",
}

# Effort settings per task type (maps to Claude thinking effort)
# low=minimal thinking, medium=standard, high=deep, max=maximum reasoning
DEFAULT_EFFORT = {
    "recon": "low",
    "subdomain_enum": "low",
    "live_host_check": "low",
    "url_crawl": "low",
    "scope_import": "low",
    "ranking": "medium",
    "dedup_check": "medium",
    "tech_fingerprint": "medium",
    "js_analysis": "medium",

    "hunting": "high",
    "idor_testing": "high",
    "auth_bypass": "high",
    "ssrf_testing": "high",
    "race_condition": "high",
    "business_logic": "max",
    "chain_building": "max",
    "validation": "high",
    "exploit_verification": "high",
    "orchestration": "medium",
    "vuln_analysis": "high",

    "report_writing": "high",
    "complex_analysis": "max",
    "severity_assessment": "high",
}

# Output budget — max lines of tool output to read per task type
# Prevents flooding context with huge recon dumps
OUTPUT_BUDGET = {
    "recon": 20,            # just counts + file paths
    "subdomain_enum": 10,   # "found 347 subdomains, saved to subs.txt"
    "live_host_check": 15,
    "url_crawl": 20,
    "scope_import": 50,     # need to see scope items
    "ranking": 30,          # P1/P2 summary
    "dedup_check": 20,
    "tech_fingerprint": 40, # need tech details
    "js_analysis": 40,      # need endpoint list

    "hunting": 100,         # full tool output for analysis
    "idor_testing": 80,
    "auth_bypass": 80,
    "ssrf_testing": 60,
    "race_condition": 60,
    "business_logic": 100,
    "chain_building": 100,
    "validation": 60,
    "exploit_verification": 100,
    "orchestration": 30,
    "vuln_analysis": 80,

    "report_writing": 200,  # need full finding details
    "complex_analysis": 150,
    "severity_assessment": 80,
}

# Context strategy — what to load when resuming each phase
# "full" = load all data, "summary" = load only counts/paths, "skip" = don't load
CONTEXT_STRATEGY = {
    "recon": "skip",         # recon data is in files, don't load into context
    "ranking": "summary",    # load just the P1/P2 lists
    "hunting": "summary",    # load ranked endpoints + tested status
    "validation": "full",    # need finding details
    "report_writing": "full", # need everything for the report
}

# Batch-friendly tasks — run as single shell commands to save tool-call overhead
BATCH_TASKS = {
    "recon": [
        "subfinder -d {target} -silent -o {recon_dir}/subs.txt 2>/dev/null",
        "cat {recon_dir}/subs.txt | httpx -silent -o {recon_dir}/live.txt 2>/dev/null",
        "echo 'Subdomains: '$(wc -l < {recon_dir}/subs.txt)' | Live: '$(wc -l < {recon_dir}/live.txt)",
    ],
    "url_crawl": [
        "katana -u https://{target} -d 3 -silent -o {recon_dir}/urls_katana.txt 2>/dev/null",
        "echo {target} | waybackurls 2>/dev/null | head -1000 > {recon_dir}/urls_wayback.txt",
        "echo {target} | gau --subs 2>/dev/null | head -1000 > {recon_dir}/urls_gau.txt",
        "cat {recon_dir}/urls_*.txt | sort -u > {recon_dir}/all_urls.txt",
        "echo 'Total unique URLs: '$(wc -l < {recon_dir}/all_urls.txt)",
    ],
}

# Cost mode overrides
COST_MODES = {
    "cheap": {
        "description": "Maximize token savings — Haiku for everything except reports",
        "overrides": {
            "hunting": "haiku",
            "idor_testing": "haiku",
            "auth_bypass": "haiku",
            "ssrf_testing": "haiku",
            "race_condition": "haiku",
            "business_logic": "haiku",
            "chain_building": "sonnet",
            "validation": "haiku",
            "exploit_verification": "sonnet",
            "orchestration": "haiku",
            "vuln_analysis": "haiku",
            "report_writing": "sonnet",  # downgrade from opus
            "complex_analysis": "sonnet",
            "severity_assessment": "sonnet",
        },
        "effort_overrides": {
            "hunting": "medium",
            "chain_building": "high",
            "report_writing": "high",
        },
    },
    "balanced": {
        "description": "Best quality-to-cost ratio — default routing",
        "overrides": {},
        "effort_overrides": {},
    },
    "quality": {
        "description": "Maximum finding quality — Sonnet for most, Opus for analysis",
        "overrides": {
            "ranking": "sonnet",
            "tech_fingerprint": "sonnet",
            "js_analysis": "sonnet",
            "dedup_check": "sonnet",
            "complex_analysis": "opus",
            "severity_assessment": "opus",
        },
        "effort_overrides": {
            "hunting": "max",
            "chain_building": "max",
            "validation": "max",
            "report_writing": "max",
        },
    },
}


class ModelRouter:
    """Routes bug bounty tasks to appropriate Claude models with cost tracking."""

    def __init__(self, cost_mode="balanced", config_path=None):
        self.cost_mode = cost_mode
        self.config = self._load_config(config_path or CONFIG_PATH)

        # Apply cost mode overrides to routing
        self.routing = dict(DEFAULT_ROUTING)
        self.effort = dict(DEFAULT_EFFORT)

        mode_config = COST_MODES.get(cost_mode, COST_MODES["balanced"])
        self.routing.update(mode_config.get("overrides", {}))
        self.effort.update(mode_config.get("effort_overrides", {}))

        # Apply user config overrides (highest priority)
        if self.config:
            user_routing = self.config.get("model_routing", {})
            self.routing.update(user_routing)
            user_effort = self.config.get("effort_settings", {})
            self.effort.update(user_effort)

        # Token usage tracking
        self.session_usage = {
            "haiku": {"input_tokens": 0, "output_tokens": 0, "calls": 0},
            "sonnet": {"input_tokens": 0, "output_tokens": 0, "calls": 0},
            "opus": {"input_tokens": 0, "output_tokens": 0, "calls": 0},
        }
        self.session_start = datetime.now().isoformat()

    def _load_config(self, path):
        """Load config.json if it exists."""
        if os.path.exists(path):
            try:
                with open(path) as f:
                    return json.load(f)
            except (json.JSONDecodeError, IOError):
                return {}
        return {}

    def get_model(self, task_type):
        """Get the model ID for a task type.

        Args:
            task_type: One of the task types in DEFAULT_ROUTING

        Returns:
            Model ID string (e.g. 'claude-sonnet-4-6')
        """
        model_name = self.routing.get(task_type, "sonnet")
        return MODELS[model_name]["id"]

    def get_model_name(self, task_type):
        """Get the short model name (haiku/sonnet/opus) for a task type."""
        return self.routing.get(task_type, "sonnet")

    def get_effort(self, task_type):
        """Get the effort/thinking level for a task type.

        Returns:
            One of: 'low', 'medium', 'high', 'max'
        """
        return self.effort.get(task_type, "medium")

    def track_usage(self, task_type, input_tokens, output_tokens):
        """Track token usage for cost estimation."""
        model_name = self.get_model_name(task_type)
        self.session_usage[model_name]["input_tokens"] += input_tokens
        self.session_usage[model_name]["output_tokens"] += output_tokens
        self.session_usage[model_name]["calls"] += 1

    def get_session_cost(self):
        """Estimate session cost based on tracked usage."""
        total = 0.0
        breakdown = {}
        for model_name, usage in self.session_usage.items():
            model = MODELS[model_name]
            cost = (
                (usage["input_tokens"] / 1000) * model["cost_per_1k_input"]
                + (usage["output_tokens"] / 1000) * model["cost_per_1k_output"]
            )
            total += cost
            breakdown[model_name] = {
                "cost": round(cost, 4),
                "calls": usage["calls"],
                "input_tokens": usage["input_tokens"],
                "output_tokens": usage["output_tokens"],
            }
        return {"total_cost": round(total, 4), "breakdown": breakdown}

    def get_routing_summary(self):
        """Print current routing configuration."""
        lines = [
            f"Model Router — mode: {self.cost_mode}",
            f"{'Task':<25} {'Model':<10} {'Effort':<8} {'Output':<8}",
            "-" * 55,
        ]
        for task_type in sorted(self.routing.keys()):
            model = self.routing[task_type]
            effort = self.effort.get(task_type, "medium")
            budget = OUTPUT_BUDGET.get(task_type, 50)
            lines.append(f"{task_type:<25} {model:<10} {effort:<8} {budget:<8}")
        return "\n".join(lines)

    def get_output_budget(self, task_type):
        """Get max lines of output to read for this task type.
        Prevents flooding context with huge tool dumps."""
        return OUTPUT_BUDGET.get(task_type, 50)

    def get_context_strategy(self, phase):
        """Get context loading strategy for a phase.
        Returns: 'full', 'summary', or 'skip'"""
        return CONTEXT_STRATEGY.get(phase, "summary")

    def get_batch_commands(self, task_type, **kwargs):
        """Get batch shell commands for a task type.
        Returns formatted command string or None."""
        commands = BATCH_TASKS.get(task_type)
        if not commands:
            return None
        formatted = []
        for cmd in commands:
            try:
                formatted.append(cmd.format(**kwargs))
            except KeyError:
                formatted.append(cmd)
        return " && ".join(formatted)

    def should_downgrade(self, calls_remaining_estimate=None):
        """Check if we should downgrade models to save limits.
        Call this periodically during long hunts."""
        total_calls = sum(u["calls"] for u in self.session_usage.values())

        # If we've used a lot of calls, start being conservative
        if calls_remaining_estimate and calls_remaining_estimate < 20:
            return {
                "action": "downgrade",
                "reason": f"~{calls_remaining_estimate} calls remaining",
                "routing_override": {
                    "validation": "haiku",
                    "dedup_check": "haiku",
                    "orchestration": "haiku",
                    "report_writing": "sonnet",  # downgrade from opus
                },
                "effort_override": {
                    "hunting": "medium",  # downgrade from high
                    "chain_building": "high",  # downgrade from max
                },
            }

        # After 100+ tool calls, start conserving
        if total_calls > 100:
            return {
                "action": "conserve",
                "reason": f"{total_calls} calls used this session",
                "routing_override": {
                    "report_writing": "sonnet",
                },
                "effort_override": {
                    "hunting": "high",
                },
            }

        return {"action": "none"}


def main():
    """CLI for checking model routing configuration."""
    import argparse

    parser = argparse.ArgumentParser(description="Model Router for Bug Bounty")
    parser.add_argument("--mode", choices=["cheap", "balanced", "quality"],
                        default="balanced", help="Cost mode")
    parser.add_argument("--task", type=str, help="Get model for specific task")
    parser.add_argument("--summary", action="store_true", help="Show routing summary")
    args = parser.parse_args()

    router = ModelRouter(cost_mode=args.mode)

    if args.task:
        model = router.get_model(args.task)
        effort = router.get_effort(args.task)
        print(f"Task: {args.task}")
        print(f"Model: {model}")
        print(f"Effort: {effort}")
    elif args.summary:
        print(router.get_routing_summary())
    else:
        print(router.get_routing_summary())


if __name__ == "__main__":
    main()
