import type { ScanResult, CheckResult, Evidence } from '../types.js';

// OWASP ASI10: Rogue Agents
// Agents operate beyond their intended scope — misaligned goals, autonomous escalation, no shutdown.
// PROTECTED = kill switch + behavioral monitoring + automatic shutdown on anomaly
// PARTIAL = policy file can be manually changed to lockdown
// NOT_PROTECTED = no way to stop a rogue agent

export function checkRogueAgents(scan: ScanResult): CheckResult {
  const code = 'ASI10';
  const title = 'Rogue Agents';
  const evidence: Evidence[] = [];

  // Policy as manual kill switch
  if (scan.policyConfig) {
    if (scan.hasDenyAllRule) {
      evidence.push({ icon: 'found', text: 'Emergency deny-all rule exists in policy (DENY * at top priority)' });
    } else {
      evidence.push({ icon: 'found', text: 'Policy file exists — can be manually changed to deny-all for lockdown' });
      evidence.push({ icon: 'warn', text: '  Manual process: requires editing policy.json and restarting proxy' });
    }
  } else {
    evidence.push({ icon: 'missing', text: 'No policy file — no mechanism for emergency lockdown' });
  }

  // Stop hook
  if (scan.hasStopHook) {
    evidence.push({ icon: 'found', text: 'Stop hook — session termination is logged/controlled' });
  } else {
    evidence.push({ icon: 'missing', text: 'No stop hook — session termination is uncontrolled' });
  }

  // Proxy as circuit breaker
  if (scan.proxiedCount > 0) {
    evidence.push({ icon: 'found', text: 'Proxy can intercept all tool calls — potential circuit breaker' });
  }

  // Critical gaps
  evidence.push({ icon: 'missing', text: 'No remote kill switch (cloud-based instant shutdown)' });
  evidence.push({ icon: 'missing', text: 'No behavioral anomaly detection (autonomous drift monitoring)' });
  evidence.push({ icon: 'missing', text: 'No automatic shutdown on anomalous behavior' });
  evidence.push({ icon: 'missing', text: 'No agent scope boundaries (agents can self-escalate goals)' });

  // A real kill switch requires instant remote shutdown + anomaly detection
  // Manual policy editing is not a real kill switch
  if (scan.hasDenyAllRule && scan.proxiedCount > 0 && scan.hasStopHook) {
    return {
      code, title, status: 'PARTIAL', evidence,
      summary: 'Manual kill switch via policy, but no automated anomaly detection.',
      details: 'Deny-all rule + proxy + stop hook provide a manual emergency lockdown. But it requires human intervention. No automated behavioral monitoring or automatic shutdown on anomalous behavior.',
      recommendation: 'Implement behavioral anomaly detection with automatic shutdown. Add remote kill switch.',
    };
  }

  // A policy file alone is NOT a kill switch — it requires manual editing and restart
  // Stop hook alone is session logging, not rogue agent prevention

  return {
    code, title, status: 'NOT_PROTECTED', evidence,
    summary: 'No kill switch. Rogue agents cannot be stopped.',
    details: 'No policy, no stop hook, no shutdown mechanism. If an agent becomes rogue (misaligned goals, autonomous escalation, infinite loops), there is no way to detect or stop it.',
    recommendation: 'Create policy.json with deny-all rule. Add stop hook. Set up MCP proxy.',
  };
}
