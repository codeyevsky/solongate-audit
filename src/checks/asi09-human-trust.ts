import type { ScanResult, CheckResult, Evidence } from '../types.js';

// OWASP ASI09: Human-Agent Trust Exploitation
// Agents manipulate approvers through deceptive framing, approval fatigue, or social engineering.
// OWASP mitigations: raw intent routing (show actual args, not agent summaries),
// policy-generated explanations (never agent-generated), verified agentId in approval requests.

export function checkHumanTrust(scan: ScanResult): CheckResult {
  const code = 'ASI09';
  const title = 'Human-Agent Trust';
  const evidence: Evidence[] = [];

  // OWASP: Raw intent routing — show actual tool calls, not agent's reframing
  if (scan.hasRawIntentDisplay) {
    evidence.push({ icon: 'found', text: 'Raw intent routing — approvers see actual tool call arguments, not agent summaries' });
  } else {
    evidence.push({ icon: 'missing', text: 'No raw intent routing — approvers may see agent-reframed summaries instead of actual arguments (OWASP: critical)' });
  }

  // OWASP: Approval routing — route critical actions to human reviewers
  if (scan.hasApprovalRouting) {
    evidence.push({ icon: 'found', text: 'Approval routing — high-impact actions routed to human reviewers' });
  } else {
    evidence.push({ icon: 'missing', text: 'No approval routing — no human review gate for critical agent actions' });
  }

  // OWASP: Policy-generated explanations (never agent-generated)
  if (scan.hasApprovalRouting && scan.policyConfig) {
    evidence.push({ icon: 'found', text: 'Policy-generated explanations — approval context comes from policy engine, not agent' });
  } else {
    evidence.push({ icon: 'missing', text: 'No policy-generated explanations — agents can frame approval requests deceptively' });
  }

  // Pre-tool hooks (closest to human-in-the-loop, but automated)
  if (scan.hasPreToolHook) {
    evidence.push({ icon: 'found', text: 'Pre-tool hooks — can gate tool execution' });
    evidence.push({ icon: 'warn', text: '  But: hooks are automated scripts, not true human approval' });
  } else {
    evidence.push({ icon: 'missing', text: 'No pre-tool hooks — no gate before tool execution' });
  }

  // Post-tool audit
  if (scan.hasPostToolHook || scan.hasAuditHook) {
    evidence.push({ icon: 'found', text: 'Post-tool audit — tool actions are logged for after-the-fact review' });
  } else {
    evidence.push({ icon: 'missing', text: 'No audit hooks — agent actions are not logged' });
  }

  // Proxy logs decisions
  if (scan.proxiedCount > 0) {
    evidence.push({ icon: 'found', text: 'Proxy logs tool call decisions (ALLOW/DENY) with reasoning' });
  }

  // OWASP: Verified agentId in approval requests
  if (scan.hasPrincipalBinding) {
    evidence.push({ icon: 'found', text: 'Verified agentId in requests — approvers see real identity, not self-reported' });
  } else {
    evidence.push({ icon: 'missing', text: 'No verified agentId — approvers cannot confirm which agent is requesting action' });
  }

  // Critical OWASP gaps
  evidence.push({ icon: 'missing', text: 'No protection against approval fatigue (repeated low-risk requests to desensitize humans)' });
  evidence.push({ icon: 'missing', text: 'No agent output verification mechanism (humans may over-trust agent outputs)' });

  // PROTECTED: raw intent + approval routing + policy explanations
  if (scan.hasRawIntentDisplay && scan.hasApprovalRouting) {
    return {
      code, title, status: 'PROTECTED', evidence,
      summary: 'Human approval with raw intent routing and policy-generated explanations.',
      details: 'Approvers see actual tool call arguments (raw intent), not agent summaries. Explanations come from policy engine, not agents. Critical actions require human approval. Agents cannot game the approval process.',
    };
  }

  // PARTIAL: some human oversight exists but not OWASP-compliant
  if (scan.hasApprovalRouting || scan.hasRawIntentDisplay) {
    return {
      code, title, status: 'PARTIAL', evidence,
      summary: 'Some human approval exists but incomplete trust exploitation defense.',
      details: scan.hasApprovalRouting
        ? 'Actions are routed for approval but approvers may see agent-generated summaries. Agents can manipulate framing to get approvals.'
        : 'Raw intent is shown but no approval routing — humans see real args but cannot block actions.',
      recommendation: 'Add both raw intent routing AND approval routing. Ensure explanations are policy-generated.',
    };
  }

  // NOT_PROTECTED
  return {
    code, title, status: 'NOT_PROTECTED', evidence,
    summary: 'No human oversight. Agents act without human review or approval.',
    details: 'No raw intent routing, no approval workflow, no policy-generated explanations. Agents can frame requests deceptively, exploit approval fatigue, and manipulate human trust. OWASP: "Route unmodified tool calls to approvers, not agent summaries."',
    recommendation: 'Implement approval routing for critical actions. Add raw intent display. Ensure policy-generated explanations.',
  };
}
