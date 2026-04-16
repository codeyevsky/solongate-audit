import type { ScanResult, CheckResult, Evidence } from '../types.js';

// OWASP ASI04: Agentic Supply Chain Vulnerabilities
// Malicious or compromised dependencies (MCP servers, frameworks, tools) introduce attacks.
// OWASP mitigations: allowlist enforcement at gateway with deny-default fallback,
// block undeclared tool calls, validate tool call shapes against policy.

export function checkSupplyChain(scan: ScanResult): CheckResult {
  const code = 'ASI04';
  const title = 'Supply Chain';
  const evidence: Evidence[] = [];

  // OWASP: Allowlist enforcement — deny-undeclared-default rule
  if (scan.hasDenyUndeclaredDefault) {
    evidence.push({ icon: 'found', text: 'Deny-undeclared-default rule — blocks any tool call to undeclared actions' });
  } else {
    evidence.push({ icon: 'missing', text: 'No deny-undeclared-default rule — injected/unknown tools are not blocked (OWASP: deny-default fallback)' });
  }

  // OWASP: Tool allowlist — only declared tools can be called
  if (scan.hasToolAllowlist) {
    evidence.push({ icon: 'found', text: 'Tool allowlist — only explicitly allowed tools can be invoked' });
  } else {
    evidence.push({ icon: 'missing', text: 'No tool allowlist — any tool can be called if not explicitly denied' });
  }

  // MCP servers using @latest (critical — version can change anytime)
  const latestServers = scan.servers.filter((s) => s.usesLatest);
  if (latestServers.length > 0) {
    evidence.push({ icon: 'warn', text: `${latestServers.length} MCP server(s) use @latest tag — unpinned, can change without notice` });
    for (const s of latestServers) {
      evidence.push({ icon: 'warn', text: `  ${s.name}: uses @latest` });
    }
  } else if (scan.servers.length > 0) {
    evidence.push({ icon: 'found', text: 'No @latest tags detected in MCP server configs' });
  }

  // Lock file
  if (scan.hasLockFile) {
    evidence.push({ icon: 'found', text: 'Lock file present — dependency versions reproducible' });
  } else {
    evidence.push({ icon: 'missing', text: 'No lock file — dependency versions may vary between installs' });
  }

  // Wildcard versions
  if (scan.hasWildcardVersions) {
    evidence.push({ icon: 'warn', text: 'Wildcard (*) or "latest" versions in package.json' });
  } else if (scan.packageJson) {
    evidence.push({ icon: 'found', text: 'All dependency versions are pinned (no wildcards)' });
  }

  // Dependabot
  if (scan.hasDependabot) {
    evidence.push({ icon: 'found', text: 'Dependabot configured — automated vulnerability patching' });
  } else {
    evidence.push({ icon: 'missing', text: 'No Dependabot/Renovate — known vulnerabilities may go unpatched' });
  }

  // Secrets in git
  if (scan.hasEnvFile && !scan.gitignoreHasEnv) {
    evidence.push({ icon: 'warn', text: '.env file exists but NOT in .gitignore — secrets may leak' });
  } else if (scan.hasEnvFile && scan.gitignoreHasEnv) {
    evidence.push({ icon: 'found', text: '.env excluded from version control (.gitignore)' });
  }

  // Pre-commit hooks
  if (scan.hasPreCommitHooks) {
    evidence.push({ icon: 'found', text: 'Pre-commit hooks — can catch secrets/issues before commit' });
  }

  // OWASP: Gateway validates tool call shapes against declared policy
  if (scan.proxiedCount > 0 && scan.denyRules.length > 0) {
    evidence.push({ icon: 'found', text: 'Gateway proxy validates tool calls against policy rules' });
  } else {
    evidence.push({ icon: 'missing', text: 'No gateway validation of tool call shapes against policy' });
  }

  // Score
  const hasLatestRisk = latestServers.length > 0;
  const hasLock = scan.hasLockFile;
  const noPinIssues = !scan.hasWildcardVersions && !hasLatestRisk;

  // PROTECTED: deny-undeclared + allowlist + pinned + lock + dependabot
  if (scan.hasDenyUndeclaredDefault && hasLock && noPinIssues && scan.hasDependabot) {
    return {
      code, title, status: 'PROTECTED', evidence,
      summary: 'Supply chain secured with tool allowlist, pinned versions, and automated scanning.',
      details: 'Deny-undeclared-default blocks injected tools. All versions pinned. Lock file ensures reproducibility. Dependabot monitors vulnerabilities. Gateway validates tool shapes.',
    };
  }

  if (hasLock && !scan.hasWildcardVersions) {
    return {
      code, title, status: 'PARTIAL', evidence,
      summary: 'Dependencies mostly pinned but gaps remain.',
      details: hasLatestRisk
        ? 'MCP servers use @latest — a compromised update could inject malicious tools. No deny-undeclared-default rule to block unknown tools.'
        : 'Lock file and pinned versions help, but no tool allowlist or automated scanning.',
      recommendation: scan.hasDenyUndeclaredDefault
        ? 'Pin MCP server versions. Add Dependabot.'
        : 'Add deny-undeclared-default rule in policy. Pin MCP versions. Add Dependabot.',
    };
  }

  return {
    code, title, status: 'NOT_PROTECTED', evidence,
    summary: 'Supply chain is not secured. Unpinned dependencies and no tool validation.',
    details: 'Unpinned versions, @latest MCP servers, no tool allowlist, and no deny-undeclared-default. A compromised package or MCP server can inject malicious tools or steal data. "32% of MCP servers have critical vulnerabilities" — OWASP.',
    recommendation: 'Pin all versions. Create lock file. Add deny-undeclared-default rule. Add tool allowlist. Add Dependabot.',
  };
}
