# Hunt Vault — Cross-Hunt Knowledge Base

This vault stores reusable knowledge across different bug bounty targets.
NOT for runtime state (that's hunt-memory/ + hunt_state.py).

## When to write here
- After a successful bounty: what technique worked and why
- After discovering a WAF bypass that could apply to other targets
- After finding a common misconfiguration pattern
- During /methodology review sessions

## When NOT to write here
- During active hunting (hunt_state.py handles that automatically via hooks)
- For target-specific data (that goes in hunt-memory/<target>/)

## Optional: Vault MCP for cross-hunt knowledge
```bash
claude mcp add-json hunt-vault '{"type":"stdio","command":"npx","args":["-y","@bitbonsai/mcpvault@latest","./hunt-vault"]}' --scope project
```
This lets Claude search the vault without reading entire files into context.
