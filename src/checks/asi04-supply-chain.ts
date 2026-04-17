import type { AuditData, CheckResult, Evidence } from '../types.js';

// OWASP ASI04: Agentic Supply Chain Vulnerabilities
// Analyze logs for risky package installs, @latest usage, unverified tool calls.

export function checkSupplyChain(data: AuditData): CheckResult {
  const code = 'ASI04';
  const title = 'Supply Chain';
  const evidence: Evidence[] = [];

  let latestInstalls = 0;
  let unpinnedInstalls = 0;
  let unknownTools = 0;
  const flagged: string[] = [];

  // Known safe tool prefixes
  const knownTools = ['read', 'write', 'edit', 'glob', 'grep', 'bash', 'shell', 'exec', 'list', 'search',
    'file', 'directory', 'notebook', 'web', 'browser', 'navigate', 'screenshot', 'mcp_filesystem',
    'mcp_playwright', 'task', 'todo', 'memory', 'ask'];

  for (const tc of data.sessions.flatMap((s) => s.toolCalls)) {
    const argStr = JSON.stringify(tc.arguments).toLowerCase();
    const toolLower = tc.toolName.toLowerCase();

    // Check for npm/pip install with @latest or unpinned
    if (toolLower.includes('bash') || toolLower.includes('shell') || toolLower.includes('exec')) {
      if (argStr.includes('npm install') || argStr.includes('npm i ') || argStr.includes('pnpm add') || argStr.includes('yarn add')) {
        if (argStr.includes('@latest')) {
          latestInstalls++;
          if (flagged.length < 5) flagged.push(`${tc.toolName}: installed package with @latest`);
        }
        // Check for install without specific version
        if (!/@\d+\.\d+/.test(argStr) && !argStr.includes('@latest')) {
          unpinnedInstalls++;
        }
      }
      if (argStr.includes('pip install') && !argStr.includes('==')) {
        unpinnedInstalls++;
        if (flagged.length < 5) flagged.push(`${tc.toolName}: pip install without pinned version`);
      }
    }

    // Check for unknown/unexpected tools
    if (!knownTools.some((kt) => toolLower.includes(kt))) {
      unknownTools++;
    }
  }

  evidence.push({ icon: 'info', text: `Scanned ${data.totalToolCalls} tool calls for supply chain risks` });

  if (latestInstalls > 0) {
    evidence.push({ icon: 'warn', text: `${latestInstalls} package install(s) with @latest — unpinned, can change without notice` });
  }
  if (unpinnedInstalls > 0) {
    evidence.push({ icon: 'warn', text: `${unpinnedInstalls} package install(s) without pinned version` });
  }
  if (unknownTools > 0) {
    evidence.push({ icon: 'info', text: `${unknownTools} calls to non-standard tools (may include injected tools)` });
  }

  for (const f of flagged) {
    evidence.push({ icon: 'warn', text: `  ${f}` });
  }

  evidence.push({ icon: 'missing', text: 'No deny-undeclared-default rule — unknown tools are not blocked' });
  evidence.push({ icon: 'missing', text: 'No tool allowlist verification in logs' });

  const totalIssues = latestInstalls + unpinnedInstalls;

  if (totalIssues === 0) {
    return {
      code, title, status: 'PARTIAL', evidence,
      summary: 'No risky package installs detected, but no tool allowlist.',
      details: 'No @latest or unpinned package installs found in logs. But no deny-undeclared-default rule exists to block unknown tools.',
      recommendation: 'Add deny-undeclared-default rule. Add tool allowlist. Pin all package versions.',
    };
  }

  return {
    code, title, status: 'NOT_PROTECTED', evidence,
    summary: `${totalIssues} risky package install(s) detected in logs.`,
    details: 'Agents installed packages without pinned versions. A compromised package could inject malicious tools. No tool allowlist blocks unknown tools.',
    recommendation: 'Pin all package versions. Add deny-undeclared-default rule. Add tool allowlist.',
  };
}
