---
name: token-economy
description: Multi-model cost routing, 12 token-saving rules, output compression, smart batching, context hygiene, modes
---

## Multi-Model Cost Routing

**Balance: save tokens on setup, spend tokens on hunting.**

| Task | Model | Effort | Rationale |
|------|-------|--------|-----------|
| Scope import, recon setup | Haiku | Low | Parsing, no reasoning |
| WAF detect, wordlists | Haiku | Low | Tool orchestration |
| API discovery, takeover scan | Haiku | Low | Tool runs, check output |
| Nuclei/ffuf/sqlmap runs | Haiku | Low | External tools do the work |
| Reading tool output, grepping | Haiku | Low | Pattern matching, no reasoning |
| **Active hunting (IDOR, SSRF, auth)** | **Sonnet** | **High** | **This finds bounties** |
| **Chain building** | **Sonnet** | **High** | **This multiplies bounties** |
| **JWT/OAuth/2FA analysis** | **Sonnet** | **High** | **Complex exploitation** |
| **PoC + Report writing** | **Sonnet** | **High** | **Quality = acceptance** |

Modes: `--mode cheap` / `--mode balanced` (default) / `--mode quality`

## 12 Token-Saving Rules (MANDATORY)

**These rules can 2-3x your effective hunt time within the same token budget.**

### Output Compression (saves 50%+ context tokens)
1. **Never explain what you're about to do** — just do it
2. **Never echo/summarize tool output** — parse it silently, act on results
3. **Redirect large output to files** — `cmd > out.txt && wc -l out.txt` instead of dumping 500 lines into context
4. **Use `tail`/`head`/`grep` for output** — never `cat` a full file into context unless writing a report

### Smart Batching (saves 3-5x tool calls)
5. **Chain shell commands** — `subfinder | httpx | tee live.txt && wc -l live.txt` = 1 call, not 3
6. **Batch independent tests** — run multiple curl tests in a single bash script, not separate tool calls
7. **Pre-build test scripts** — write a `.sh` file with 10 tests, execute once, parse output file

### Context Window Hygiene (prevents quality degradation)
8. **Use `hunt_state.py` for persistence** — don't rely on conversation context for data
9. **Phase transitions = context reset** — when moving from recon→hunting, DON'T carry recon output forward. Load only the endpoint list
10. **Structured results** — when parsing tool output, extract to JSON: `{"url": "...", "status": 200, "finding": "IDOR"}`. Don't store raw text

### Dedup-First Strategy (prevents wasted tokens on duplicates)
11. **Check Hacktivity BEFORE deep testing** — `python3 mcp/hackerone-mcp/server.py search "<vuln-type>" --program <program>` costs 1 call vs wasting 20 on a known duplicate
12. **Skip low-value targets early** — if bounty table says max $500 for a domain, quick scan only (nuclei + 5 min manual). Don't spend 50 Sonnet calls on it
