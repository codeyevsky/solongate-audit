import type { ScanResult, CheckResult, Evidence } from '../types.js';

// OWASP ASI04: Agentic Supply Chain Vulnerabilities
// Compromised MCP servers, unpinned tool versions, malicious plugins.
// PROTECTED = pinned versions + lock file + tool validation + Dependabot
// PARTIAL = lock file exists OR versions pinned but no validation
// NOT_PROTECTED = @latest tags, no lock file, no dependency scanning

export function checkSupplyChain(scan: ScanResult): CheckResult {
  const code = 'ASI04';
  const title = 'Supply Chain';
  const evidence: Evidence[] = [];

  // MCP servers using @latest (dangerous — version can change anytime)
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

  // Score: @latest is a critical risk for supply chain
  const hasLatestRisk = latestServers.length > 0;
  const hasLock = scan.hasLockFile;
  const noPinIssues = !scan.hasWildcardVersions && !hasLatestRisk;

  if (hasLock && noPinIssues && scan.hasDependabot) {
    return {
      code, title, status: 'PROTECTED', evidence,
      summary: 'Dependencies pinned, scanned, and automatically patched.',
      details: 'Lock file ensures reproducible builds. No wildcard versions. Dependabot monitors for known vulnerabilities. MCP server versions are pinned.',
    };
  }

  if (hasLock && !scan.hasWildcardVersions) {
    return {
      code, title, status: 'PARTIAL', evidence,
      summary: 'Dependencies mostly pinned but gaps remain.',
      details: hasLatestRisk
        ? 'MCP servers use @latest — a compromised package update could inject malicious tools. Lock file exists for npm deps but MCP tool versions are unpinned.'
        : 'Lock file and pinned versions help, but no automated vulnerability scanning (Dependabot/Renovate).',
      recommendation: hasLatestRisk
        ? 'Pin MCP server versions (replace @latest with specific versions like @1.2.3).'
        : 'Add .github/dependabot.yml for automated vulnerability scanning.',
    };
  }

  return {
    code, title, status: 'NOT_PROTECTED', evidence,
    summary: 'Supply chain is not secured. Unpinned dependencies and MCP tools.',
    details: 'Unpinned dependency versions, @latest MCP servers, and no automated scanning. A compromised package or MCP server can inject malicious tools or steal data.',
    recommendation: 'Pin all versions. Create lock file. Add Dependabot. Replace @latest with specific versions.',
  };
}
