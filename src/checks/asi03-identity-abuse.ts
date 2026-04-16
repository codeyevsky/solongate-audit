import type { ScanResult, CheckResult, Evidence } from '../types.js';

// OWASP ASI03: Identity and Privilege Abuse
// Agents claim unauthorized identities or accumulate excessive permissions (confused deputy).
// OWASP mitigations: principal binding, strict identity mode, verified identity in receipts,
// reject calls where key identity doesn't match actual principal.

export function checkIdentityAbuse(scan: ScanResult): CheckResult {
  const code = 'ASI03';
  const title = 'Identity Abuse';
  const evidence: Evidence[] = [];

  const hasProxy = scan.proxiedCount > 0;
  const hasTrustMap = scan.hasAgentTrustMap;
  const hasGroups = scan.agentGroups.length > 0;
  const hasRelationships = scan.trustRelationships > 0;

  // OWASP: Principal binding — bind API keys to specific agent identities
  if (scan.hasPrincipalBinding) {
    evidence.push({ icon: 'found', text: 'Principal binding — API keys bound to specific agent identities' });
  } else {
    evidence.push({ icon: 'missing', text: 'No principal binding — API keys not bound to agent identities (OWASP: bind keys to principals)' });
  }

  // OWASP: Strict identity mode — reject mismatched identity claims
  if (scan.hasStrictIdentityMode) {
    evidence.push({ icon: 'found', text: 'Strict identity mode — rejects calls where claimed identity ≠ verified principal' });
  } else {
    evidence.push({ icon: 'missing', text: 'No strict identity mode — agents can self-report identity without verification' });
  }

  // Agent identity detection via proxy
  if (hasProxy) {
    evidence.push({ icon: 'found', text: 'MCP proxy detects agent identity via clientInfo' });
    evidence.push({ icon: 'warn', text: '  Identity is detected but not cryptographically verified' });
  } else {
    evidence.push({ icon: 'missing', text: 'No proxy — agent identity not tracked at all' });
  }

  // Trust map with per-agent privilege boundaries
  if (hasTrustMap) {
    evidence.push({ icon: 'found', text: 'Agent trust map configured in policy' });
    if (hasGroups) evidence.push({ icon: 'found', text: `  Groups: ${scan.agentGroups.join(', ')}` });
    if (hasRelationships) evidence.push({ icon: 'found', text: `  ${scan.trustRelationships} trust relationship(s) with privilege scoping` });
  } else {
    evidence.push({ icon: 'missing', text: 'No agent trust map — all agents have equal, unrestricted access' });
  }

  // Audit hooks (who did what — but logs only)
  if (scan.hasPostToolHook || scan.hasAuditHook) {
    evidence.push({ icon: 'found', text: 'Audit logging — records which agent performed which action' });
    evidence.push({ icon: 'warn', text: '  Logs only — does not actively prevent privilege abuse' });
  } else {
    evidence.push({ icon: 'missing', text: 'No audit logging — no record of which agent did what' });
  }

  // Per-server scoped API keys/tokens
  const serversWithKeys = scan.servers.filter((s) => {
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

  // OWASP: Verified principal in every receipt
  evidence.push({ icon: 'missing', text: 'No verified principal in audit receipts (OWASP: record verified, not claimed identity)' });

  // PROTECTED: principal binding + strict identity + trust map + proxy
  if (scan.hasPrincipalBinding && scan.hasStrictIdentityMode && hasTrustMap && hasProxy) {
    return {
      code, title, status: 'PROTECTED', evidence,
      summary: 'Agent identities verified via principal binding with active privilege enforcement.',
      details: 'API keys bound to agent identities. Strict identity mode rejects mismatched claims. Trust map enforces per-agent privileges. Proxy blocks unauthorized access.',
    };
  }

  // PARTIAL: identity is tracked via proxy/logs, but no principal binding or strict verification
  if (hasProxy || hasTrustMap || scan.hasPostToolHook || scan.hasAuditHook) {
    return {
      code, title, status: 'PARTIAL', evidence,
      summary: 'Agent identity tracked in logs, but no principal binding or strict verification.',
      details: 'You can see which agent did what (audit trail), but identity is self-reported, not cryptographically verified. No principal binding means API keys are not tied to specific agents. Any agent can claim any identity.',
      recommendation: 'Add principal binding (bind API keys to agent identities). Enable strict identity mode. Add agentTrustMap for per-agent privileges.',
    };
  }

  return {
    code, title, status: 'NOT_PROTECTED', evidence,
    summary: 'No agent identity tracking or privilege control.',
    details: 'Agents are anonymous. No identity detection, no principal binding, no per-agent permissions, no audit trail. Any agent can act with full privileges and impersonate other agents.',
    recommendation: 'Set up MCP proxy (tracks identity). Add principal binding. Enable strict identity mode.',
  };
}
