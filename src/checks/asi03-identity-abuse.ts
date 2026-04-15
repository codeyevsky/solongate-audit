import type { ScanResult, CheckResult, Evidence } from '../types.js';

// OWASP ASI03: Identity and Privilege Abuse
// Agents inherit or escalate privileges, impersonate users, or access resources beyond their scope.
// PROTECTED = per-agent credentials + trust map + active privilege enforcement
// PARTIAL = identity tracked (logs show who), but no active blocking/scoping
// NOT_PROTECTED = no identity tracking at all

export function checkIdentityAbuse(scan: ScanResult): CheckResult {
  const code = 'ASI03';
  const title = 'Identity Abuse';
  const evidence: Evidence[] = [];

  const hasProxy = scan.proxiedCount > 0;
  const hasTrustMap = scan.hasAgentTrustMap;
  const hasGroups = scan.agentGroups.length > 0;
  const hasRelationships = scan.trustRelationships > 0;

  // Agent identity detection
  if (hasProxy) {
    evidence.push({ icon: 'found', text: 'MCP proxy detects agent identity via clientInfo' });
    evidence.push({ icon: 'info', text: '  Logs show which agent (claude-code, cursor, etc.) made each call' });
  } else {
    evidence.push({ icon: 'missing', text: 'No proxy — agent identity not tracked' });
  }

  // Trust map
  if (hasTrustMap) {
    evidence.push({ icon: 'found', text: 'Agent trust map configured in policy' });
    if (hasGroups) evidence.push({ icon: 'found', text: `  Groups: ${scan.agentGroups.join(', ')}` });
    if (hasRelationships) evidence.push({ icon: 'found', text: `  ${scan.trustRelationships} trust relationship(s)` });
  } else {
    evidence.push({ icon: 'missing', text: 'No agent trust map — all agents have equal access' });
  }

  // Audit hooks (who did what)
  if (scan.hasPostToolHook || scan.hasAuditHook) {
    evidence.push({ icon: 'found', text: 'Audit logging — records which agent performed which action' });
    evidence.push({ icon: 'warn', text: '  Logs only — does not actively prevent privilege abuse' });
  } else {
    evidence.push({ icon: 'missing', text: 'No audit logging of agent actions' });
  }

  // Per-server env keys
  const serversWithKeys = scan.servers.filter((s) => {
    // Check if the original config has env with API_KEY/TOKEN
    const configs = [scan.mcpConfig, scan.claudeDesktopConfig, scan.cursorConfig, scan.geminiConfig, scan.openclawConfig].filter(Boolean);
    for (const cfg of configs) {
      const srv = cfg!.content.mcpServers?.[s.name];
      if (srv?.env && Object.keys(srv.env).some((k) => k.includes('KEY') || k.includes('TOKEN') || k.includes('SECRET'))) return true;
    }
    return false;
  });
  if (serversWithKeys.length > 0) {
    evidence.push({ icon: 'found', text: `${serversWithKeys.length} server(s) with scoped API keys/tokens` });
  }

  // PROTECTED requires active enforcement: trust map with relationships + proxy
  if (hasTrustMap && hasRelationships && hasProxy) {
    return {
      code, title, status: 'PROTECTED', evidence,
      summary: 'Agent identities verified and privileges actively enforced.',
      details: 'Agent trust map defines who can do what. Trust relationships enforce privilege boundaries. Proxy blocks unauthorized access.',
    };
  }

  // PARTIAL: identity is tracked, logs exist, but no active blocking
  if (hasProxy || scan.hasPostToolHook || scan.hasAuditHook) {
    return {
      code, title, status: 'PARTIAL', evidence,
      summary: 'Agent identity tracked in logs, but no active privilege enforcement.',
      details: 'You can see which agent did what (audit trail), but agents are not actively prevented from accessing resources beyond their scope. No per-agent privilege boundaries.',
      recommendation: 'Add agentTrustMap with groups and relationships to policy.json for active enforcement.',
    };
  }

  return {
    code, title, status: 'NOT_PROTECTED', evidence,
    summary: 'No agent identity tracking or privilege control.',
    details: 'Agents are anonymous. No identity detection, no per-agent permissions, no audit trail of who did what. Any agent can act with full privileges.',
    recommendation: 'Set up MCP proxy (tracks identity) and agentTrustMap (enforces privileges).',
  };
}
