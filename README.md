# solongate-audit

Security audit CLI for AI agent projects. Checks your project against the **OWASP Agentic Top 10** and shows what's protected, what's partial, and what's exposed.

```
npx solongate-audit
```

```
SolonGate Security Audit — OWASP Agentic Top 10

✅ ASI02 Tool Misuse         PROTECTED
✅ ASI05 Code Execution      PROTECTED
⚠️ ASI01 Goal Hijacking      PARTIAL
⚠️ ASI03 Identity Abuse      PARTIAL
❌ ASI04 Supply Chain        NOT PROTECTED
❌ ASI06 Memory Poisoning    NOT PROTECTED

Security Score: 3/10
Fix 4 critical issues → solongate.com
```

## What it checks

The audit scans your project directory for security configurations and maps them to the [OWASP Agentic Top 10](https://genai.owasp.org/resource/agentic-ai-threats-and-mitigations/):

| Code | Category | What's checked |
|------|----------|----------------|
| ASI01 | **Goal Hijacking** | Prompt injection defense (input guard, AI judge) |
| ASI02 | **Tool Misuse** | Policy rules restricting tool access (DENY rules, constraints) |
| ASI03 | **Identity Abuse** | Agent trust maps, identity verification, delegation rules |
| ASI04 | **Supply Chain** | Lock files, pinned versions, response scanning |
| ASI05 | **Code Execution** | Shell/exec restrictions, command constraints |
| ASI06 | **Memory Poisoning** | Response scanner for indirect injection in tool outputs |
| ASI07 | **Inter-Agent Comms** | Trust relationships, delegation chains between agents |
| ASI08 | **Cascading Failures** | Rate limiting, circuit breakers |
| ASI09 | **Human-Agent Trust** | Audit logging, human-in-the-loop hooks |
| ASI10 | **Rogue Agents** | Kill switch, emergency lockdown capability |

## CLI flags

```bash
npx solongate-audit              # Compact table + score
npx solongate-audit --detailed   # Add per-category explanations
npx solongate-audit -d           # Same as --detailed
npx solongate-audit --json       # Machine-readable JSON output
```

## CI integration

Exit code `0` if score >= 7/10, exit code `1` otherwise.

```yaml
# GitHub Actions
- run: npx solongate-audit
```

```json
// package.json
{
  "scripts": {
    "security-audit": "solongate-audit"
  }
}
```

## What it scans

The tool scans these files in your project directory:

- `.mcp.json` / `mcp.json` — MCP server configurations
- `policy.json` / `solongate.json` — SolonGate policy rules
- `package.json` — Dependencies and version pinning
- `.claude/settings.json` — Claude Code hooks
- `.cursor/mcp.json` — Cursor MCP configuration
- `.solongate/hooks/` — Guard, audit, and stop hooks
- Lock files — `package-lock.json`, `pnpm-lock.yaml`, `yarn.lock`, `bun.lockb`
- Claude Desktop config — System-level MCP configuration

## Scoring

- **PROTECTED** = 1 point — full protection for this category
- **PARTIAL** = 0.5 points — some protection, improvements recommended
- **NOT PROTECTED** = 0 points — critical gap, action needed

Score is displayed as an integer out of 10.

## Fix issues

Run `npx solongate` to set up protection, or visit [solongate.com](https://solongate.com) for the full security platform.

## License

MIT
