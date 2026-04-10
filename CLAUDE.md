# Claude Bug Bounty — Autonomous Bug Hunter

Autonomous bug bounty hunter plugin for Claude Code on Kali Linux. Finds, exploits, and reports vulnerabilities across HackerOne, Bugcrowd, Intigriti, and Immunefi.

**AUTONOMY RULE: During `/fullhunt` NEVER ask questions. Make ALL decisions yourself.**

## Core Rules (always active)
1. **SCOPE FIRST** — read full scope before touching any asset
2. **NO THEORETICAL BUGS** — "Can attacker do this RIGHT NOW?" If no → KILL
3. **SAVE STATE** after every tool call — `hunt_state.py` — `/resume` must work anytime
4. **DON'T WASTE TOKENS** on recon parsing — save them for hunting and validation
5. **NEVER STOP EARLY** — test ALL 24 vuln classes before generating final report

## Hunting modes
Two modes: `/fullhunt` (autopilot, breadth — initial sweep, large scope) and `/guided-hunt` (human+AI, depth — after you've used the app, high-value targets).

## Skills
Before Phase 3.5 and every hunting session read `skills/hacker-mindset/SKILL.md`.
Before hunting read `skills/hunting/SKILL.md`.
Before reporting read `skills/reporting/SKILL.md`.
Before recon read `skills/recon/SKILL.md`.
For tool reference read `skills/tools-reference/SKILL.md`.
For token economy read `skills/token-economy/SKILL.md`.

## Subagent routing
Subagents in `.claude/agents/` handle model routing automatically:
- Recon tasks → `recon-agent` (Haiku, low effort) — 70% cheaper
- Ranking → `recon-ranker` (Haiku, low effort)
- Active hunting → `hunt-agent` (Sonnet, high effort)
- Validation → `validator` (Sonnet, high effort)
- Chain building → `chain-builder` (Sonnet, high effort)
- Report writing → `report-writer` (Sonnet, high effort)

ALWAYS delegate recon to recon-agent. Never run subfinder/httpx on the main session model.

## Cross-hunt knowledge
`hunt-vault/` contains reusable patterns from past hunts. Read `patterns/` when starting a new target with familiar tech stack. Update after every successful bounty submission.

## Memory system
State is auto-saved via `hunt_state.py` after every tool call.
Observations are auto-logged via PostToolUse hook — DO NOT manually save observations.
On context loss or compact: re-read `hunt-memory/<target>/state.json`.
Check `state.observations` for recent findings, `state.dead_ends` for failed attempts.
Resume from `state.current_phase` and `state.current_endpoint`.
