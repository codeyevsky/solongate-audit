import type { ScanResult, CheckResult, Evidence } from '../types.js';

// OWASP ASI09: Human-Agent Trust Exploitation
// Humans over-trust agent outputs, or agents manipulate human trust to bypass approval workflows.
// PROTECTED = mandatory human approval for critical actions + full audit trail + review UI
// PARTIAL = audit trail exists but no mandatory approval workflow
// NOT_PROTECTED = no audit trail, no human oversight

export function checkHumanTrust(scan: ScanResult): CheckResult {
  const code = 'ASI09';
  const title = 'Human-Agent Trust';
  const evidence: Evidence[] = [];

  // Pre-tool hooks (closest to human-in-the-loop)
  if (scan.hasPreToolHook) {
    evidence.push({ icon: 'found', text: 'Pre-tool hooks — can gate tool execution on approval' });
    evidence.push({ icon: 'warn', text: '  But: hooks are automated scripts, not true human approval' });
  } else {
    evidence.push({ icon: 'missing', text: 'No pre-tool hooks — no approval gate before tool execution' });
  }

  // Post-tool audit
  if (scan.hasPostToolHook || scan.hasAuditHook) {
    evidence.push({ icon: 'found', text: 'Post-tool audit — tool actions are logged for review' });
  } else {
    evidence.push({ icon: 'missing', text: 'No audit hooks — agent actions are not logged' });
  }

  // Logging
  if (scan.loggingDeps.length > 0) {
    evidence.push({ icon: 'found', text: `Logging library: ${scan.loggingDeps.join(', ')}` });
  }

  // Proxy logs decisions
  if (scan.proxiedCount > 0) {
    evidence.push({ icon: 'found', text: 'Proxy logs tool call decisions (ALLOW/DENY) with reasoning' });
  }

  // Critical gaps
  evidence.push({ icon: 'missing', text: 'No mandatory human approval for high-impact actions' });
  evidence.push({ icon: 'missing', text: 'No human review dashboard for agent decisions' });
  evidence.push({ icon: 'missing', text: 'No agent output verification mechanism (humans may over-trust)' });

  // True human-agent trust requires REAL human-in-the-loop approval workflows
  // Hooks are automated scripts — they run code, not ask humans for permission
  // Proxy logs are after-the-fact records, not approval gates
  // Nothing currently provides: mandatory human approval, review dashboard, output verification
  // The honest assessment: this is NOT solved by any current tooling

  return {
    code, title, status: 'NOT_PROTECTED', evidence,
    summary: 'No human oversight. Agents act without human review or approval.',
    details: 'Hooks and proxy logs provide some visibility, but no mandatory human approval workflow exists. Humans cannot review, approve, or reject high-impact agent actions before execution. No mechanism to prevent humans from over-trusting agent outputs.',
    recommendation: 'Implement human-in-the-loop approval for critical actions. Add review dashboard. Add output verification.',
  };
}
