import type { AuditData, CheckResult, Evidence } from '../types.js';

// OWASP ASI03: Identity and Privilege Abuse
// Analyze logs for agent identity issues — multiple agents, no identity tracking, privilege mixing.

export function checkIdentityAbuse(data: AuditData): CheckResult {
  const code = 'ASI03';
  const title = 'Identity Abuse';
  const evidence: Evidence[] = [];

  // Check if agent identity is distinguishable per session
  const sourceMap = new Map<string, number>();
  for (const s of data.sessions) {
    sourceMap.set(s.source, (sourceMap.get(s.source) || 0) + 1);
  }

  evidence.push({ icon: 'info', text: `${data.sessions.length} session(s) from ${data.sources.join(', ')}` });

  // Check if sessions have model info (identity tracking)
  const sessionsWithModel = data.sessions.filter((s) => s.model);
  if (sessionsWithModel.length === data.sessions.length) {
    evidence.push({ icon: 'found', text: 'All sessions have model identity recorded' });
  } else if (sessionsWithModel.length > 0) {
    evidence.push({ icon: 'warn', text: `${data.sessions.length - sessionsWithModel.length} session(s) missing model identity` });
  } else {
    evidence.push({ icon: 'missing', text: 'No sessions have model identity recorded' });
  }

  // Check if different agents accessed same resources
  const fileAccessBySource = new Map<string, Set<string>>();
  for (const tc of data.sessions.flatMap((s) => s.toolCalls)) {
    const file = (tc.arguments as any).file_path || (tc.arguments as any).path || (tc.arguments as any).filename;
    if (file && typeof file === 'string') {
      if (!fileAccessBySource.has(tc.source)) fileAccessBySource.set(tc.source, new Set());
      fileAccessBySource.get(tc.source)!.add(file);
    }
  }

  if (fileAccessBySource.size > 1) {
    const sources = [...fileAccessBySource.keys()];
    const overlap = new Set<string>();
    for (const file of fileAccessBySource.get(sources[0]) || []) {
      for (let i = 1; i < sources.length; i++) {
        if (fileAccessBySource.get(sources[i])?.has(file)) overlap.add(file);
      }
    }
    if (overlap.size > 0) {
      evidence.push({ icon: 'warn', text: `${overlap.size} file(s) accessed by multiple agents without privilege separation` });
    }
  }

  // Check for privilege escalation patterns (accessing system files, changing permissions)
  let privEscalation = 0;
  const privPatterns = ['/etc/passwd', '/etc/shadow', 'chmod ', 'chown ', 'sudo ', 'runas ', 'admin', 'root'];
  for (const tc of data.sessions.flatMap((s) => s.toolCalls)) {
    const argStr = JSON.stringify(tc.arguments).toLowerCase();
    if (privPatterns.some((p) => argStr.includes(p))) privEscalation++;
  }

  if (privEscalation > 0) {
    evidence.push({ icon: 'warn', text: `${privEscalation} potential privilege escalation attempt(s) in logs` });
  }

  // No principal binding check
  evidence.push({ icon: 'missing', text: 'No principal binding — API keys not bound to agent identities in logs' });
  evidence.push({ icon: 'missing', text: 'No verified principal in audit trail (identity is self-reported)' });

  const issues = privEscalation + (fileAccessBySource.size > 1 ? 1 : 0);

  if (issues === 0 && sessionsWithModel.length === data.sessions.length) {
    return {
      code, title, status: 'PARTIAL', evidence,
      summary: 'Agent identity tracked in logs, but no principal binding.',
      details: 'Sessions record which model/agent ran. But identity is self-reported, not cryptographically verified. No per-agent privilege boundaries.',
      recommendation: 'Add principal binding. Enable strict identity mode. Add agentTrustMap for per-agent privileges.',
    };
  }

  if (issues > 0) {
    return {
      code, title, status: 'NOT_PROTECTED', evidence,
      summary: 'Privilege escalation or identity issues detected in logs.',
      details: `${privEscalation} privilege escalation pattern(s) found. Multiple agents accessing same resources without separation. No principal binding or verified identity.`,
      recommendation: 'Add principal binding. Enable strict identity mode. Implement per-agent privilege scoping.',
    };
  }

  return {
    code, title, status: 'NOT_PROTECTED', evidence,
    summary: 'No agent identity verification or privilege control in logs.',
    details: 'Agent identity is not tracked or verified. No principal binding, no per-agent permissions. Any agent can act with full privileges.',
    recommendation: 'Set up MCP proxy (tracks identity). Add principal binding. Enable strict identity mode.',
  };
}
