# solongate-audit

AI agent audit log tool. Scans real session logs from **Claude Code**, **Gemini CLI**, and **OpenClaw**, then checks them against the **OWASP Agentic Top 10 (2026)**.

```bash
npx solongate-audit
```

```
SolonGate Security Audit — OWASP Agentic Top 10

  AI Tools: Claude Code, Gemini CLI, OpenClaw
  Sessions: 33 total, 5104 tool calls
  Period: 30.12.2025 — 17.04.2026

❌ ASI01 Goal Hijacking     NOT PROTECTED
❌ ASI02 Tool Misuse        NOT PROTECTED
⚠️ ASI03 Identity Abuse     PARTIAL
...

  Security Score: 2/10
  Fix 8 critical issues → solongate.com
```

## How it works

1. Reads AI tool session logs from your machine (not the network)
2. Extracts every tool call — name, arguments, result, timestamp
3. Analyzes patterns against OWASP Agentic Top 10 (ASI01–ASI10)
4. Reports PROTECTED / PARTIAL / NOT PROTECTED per category

## What it checks

| Code | Category | What's analyzed in logs |
|------|----------|------------------------|
| ASI01 | **Goal Hijacking** | Prompt injection patterns in tool args & results |
| ASI02 | **Tool Misuse** | Sensitive file access, destructive commands, data exfiltration |
| ASI03 | **Identity Abuse** | Model identity, privilege escalation, multi-agent overlap |
| ASI04 | **Supply Chain** | Unpinned package installs, unknown tools |
| ASI05 | **Code Execution** | Shell injection, eval, sandbox detection |
| ASI06 | **Memory Poisoning** | MINJA patterns in tool results, unscanned outputs |
| ASI07 | **Inter-Agent Comms** | Multi-agent delegation, receipt chains, fan-out |
| ASI08 | **Cascading Failures** | Error rates, burst patterns, retry storms |
| ASI09 | **Human-Agent Trust** | Deploy/publish without approval, raw intent routing |
| ASI10 | **Rogue Agents** | Volume spikes, scope escalation, behavioral anomalies |

## Default log locations

These are scanned automatically — no configuration needed:

| AI Tool | Log location |
|---------|-------------|
| Claude Code | `~/.claude/projects/<project>/<session>.jsonl` |
| Gemini CLI | `~/.gemini/tmp/<project>/chats/session-*.json` |
| OpenClaw | `~/.openclaw/agents/main/sessions/<session>.jsonl` |

## Custom log directories

Add extra directories if your logs are in a non-standard location:

```bash
# Add a custom directory
npx solongate-audit --add-dir /path/to/logs

# Add multiple
npx solongate-audit --add-dir /home/other-user/.claude/projects
npx solongate-audit --add-dir /var/log/ai-agents

# Remove a directory
npx solongate-audit --remove-dir /path/to/logs

# List all directories (default + custom)
npx solongate-audit --list-dirs

# Auto-search system for AI tool logs
npx solongate-audit --search
```

Custom directories are saved in `~/.solongate-audit/config.json` and persist across runs.

## CLI

```bash
npx solongate-audit                     # Compact report
npx solongate-audit --detailed          # Detailed analysis per category
npx solongate-audit --logs              # Show last 50 tool calls (detailed)
npx solongate-audit --logs 100          # Show last N tool calls
npx solongate-audit --watch             # Live monitoring (updates every 2s)
npx solongate-audit --json              # JSON output for CI
npx solongate-audit --help              # Show all options
```

## Export

Generate report files in multiple formats:

```bash
npx solongate-audit --export json       # Full report as JSON
npx solongate-audit --export csv        # Tool calls as CSV (Excel-compatible)
npx solongate-audit --export html       # Visual HTML report (dark theme, filterable)
npx solongate-audit --export pdf        # PDF-ready HTML (open in browser → Print → Save as PDF)
npx solongate-audit --export all        # All formats at once
```

### What each format includes

| Format | Content |
|--------|---------|
| **JSON** | Sessions, tool calls, audit results, score, metadata |
| **CSV** | One row per tool call: timestamp, source, session, model, tool call ID, tool name, arguments, result, error status |
| **HTML** | Branded visual report with score card, audit table, filterable/searchable tool call log, expandable arguments & results |
| **PDF** | Same HTML with print CSS (`@page` A4 landscape) — click "Export PDF" button or Ctrl+P |

## CI integration

Exit code `0` if score >= 7/10, exit code `1` otherwise.

```yaml
# GitHub Actions
- run: npx solongate-audit
```

### Auto-publish

When a commit is pushed to `main` with a new version in `package.json`, GitHub Actions automatically publishes to npm. No manual `npm publish` needed.

To set up: add your npm token as `NPM_TOKEN` in GitHub repo → Settings → Secrets → Actions.

## Scoring

- **PROTECTED** = 1 point
- **PARTIAL** = 0.5 points
- **NOT PROTECTED** = 0 points

Score = sum / 10 (integer).

## Install

```bash
# Run directly (no install needed)
npx solongate-audit

# Or install globally
npm install -g solongate-audit
solongate-audit

# Or add to a project
npm install --save-dev solongate-audit
```

Requires Node.js >= 18.

## Contributing

```bash
# Clone the repo
git clone https://github.com/solongate/solongate-audit.git
cd solongate-audit

# Install dependencies
npm install

# Run in dev mode
npm run dev

# Build
npm run build

# Test locally
node dist/index.js
node dist/index.js --export html
```

### Project structure

```
src/
  index.ts        CLI entry point, flag parsing
  collector.ts    Reads logs from Claude, Gemini, OpenClaw
  analyzer.ts     OWASP Agentic Top 10 checks (ASI01–ASI10)
  reporter.ts     Terminal output formatting
  export.ts       JSON, CSV, HTML, PDF export
  config.ts       Custom directory config (~/.solongate-audit/config.json)
  types.ts        TypeScript types
  spinner.ts      Loading spinner
```

### How to contribute

1. Fork the repo
2. Create a branch (`git checkout -b fix/something`)
3. Make your changes
4. Build and test (`npm run build && node dist/index.js`)
5. Commit and push
6. Open a Pull Request

Issues and feature requests: [github.com/solongate/solongate-audit/issues](https://github.com/solongate/solongate-audit/issues)

## Fix issues

Visit [solongate.com](https://solongate.com) for the full security platform.

## License

MIT
