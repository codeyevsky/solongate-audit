import type { ScanResult, CheckResult, Evidence } from '../types.js';

// OWASP ASI10: Rogue Agents
// Agents exhibit sustained behavioral misalignment — not single injections but accumulated drift.
// OWASP mitigations: CUSUM behavioral drift detection, per-agent baselines,
// thresholds (denyRateIncrease, actionVolumeSpike), remote kill switch, scope boundaries.

export function checkRogueAgents(scan: ScanResult): CheckResult {
  const code = 'ASI10';
  const title = 'Rogue Agents';
  const evidence: Evidence[] = [];

  // OWASP: CUSUM behavioral drift detection — per-agent baselines
  if (scan.hasBehavioralBaseline) {
    evidence.push({ icon: 'found', text: 'Behavioral baseline monitoring — per-agent patterns tracked for drift detection (CUSUM)' });
  } else {
    evidence.push({ icon: 'missing', text: 'No behavioral drift detection — cannot distinguish normal vs rogue behavior (OWASP: CUSUM baselines)' });
  }

  // OWASP: Remote kill switch — instant cloud-based shutdown
  if (scan.hasRemoteKillSwitch) {
    evidence.push({ icon: 'found', text: 'Remote kill switch — instant cloud-based agent shutdown' });
  } else {
    evidence.push({ icon: 'missing', text: 'No remote kill switch — cannot instantly shut down a rogue agent remotely' });
  }

  // OWASP: Automatic shutdown on anomalous behavior
  if (scan.hasAutoShutdown) {
    evidence.push({ icon: 'found', text: 'Auto-shutdown — agent automatically terminated on anomalous behavior' });
  } else {
    evidence.push({ icon: 'missing', text: 'No auto-shutdown — rogue agents continue operating even with anomalous behavior' });
  }

  // OWASP: Agent scope boundaries — prevent self-escalation
  if (scan.hasScopeBoundaries) {
    evidence.push({ icon: 'found', text: 'Scope boundaries — agents cannot self-escalate beyond defined scope' });
  } else {
    evidence.push({ icon: 'missing', text: 'No scope boundaries — agents can self-escalate goals without restriction' });
  }

  // OWASP drift thresholds
  evidence.push({ icon: 'missing', text: 'No drift thresholds (OWASP: denyRateIncrease: 2.0x, actionVolumeSpike: 3.0x)' });

  // Policy as manual kill switch (not OWASP-grade)
  if (scan.policyConfig) {
    if (scan.hasDenyAllRule) {
      evidence.push({ icon: 'found', text: 'Emergency deny-all rule exists in policy (manual lockdown)' });
    } else {
      evidence.push({ icon: 'found', text: 'Policy file exists — can be manually changed to deny-all' });
      evidence.push({ icon: 'warn', text: '  Manual process: requires editing policy.json and restarting proxy' });
    }
  } else {
    evidence.push({ icon: 'missing', text: 'No policy file — no mechanism even for manual lockdown' });
  }

  // Stop hook
  if (scan.hasStopHook) {
    evidence.push({ icon: 'found', text: 'Stop hook — session termination is logged/controlled' });
  } else {
    evidence.push({ icon: 'missing', text: 'No stop hook — session termination is uncontrolled' });
  }

  // Proxy as potential circuit breaker
  if (scan.proxiedCount > 0) {
    evidence.push({ icon: 'found', text: 'Proxy can intercept all tool calls — potential circuit breaker' });
  }

  // PROTECTED: behavioral detection + remote kill + auto-shutdown + scope boundaries
  if (scan.hasBehavioralBaseline && scan.hasRemoteKillSwitch && scan.hasAutoShutdown) {
    return {
      code, title, status: 'PROTECTED', evidence,
      summary: 'Behavioral drift detection with remote kill switch and auto-shutdown.',
      details: 'CUSUM behavioral baselines detect sustained drift patterns (not just single anomalies). Remote kill switch enables instant shutdown. Auto-shutdown triggers on threshold breach (denyRateIncrease, actionVolumeSpike). Scope boundaries prevent self-escalation.',
    };
  }

  // PARTIAL: some detection or manual kill switch
  if (scan.hasBehavioralBaseline || scan.hasRemoteKillSwitch ||
      (scan.hasDenyAllRule && scan.proxiedCount > 0 && scan.hasStopHook)) {
    return {
      code, title, status: 'PARTIAL', evidence,
      summary: scan.hasBehavioralBaseline
        ? 'Behavioral monitoring exists but no automated shutdown.'
        : 'Manual kill switch via policy, but no behavioral drift detection.',
      details: scan.hasBehavioralBaseline
        ? 'Agent behavior is monitored for drift. But no automatic shutdown when anomaly detected — requires human intervention.'
        : 'Deny-all rule + proxy + stop hook provide manual emergency lockdown. But no automated behavioral monitoring (OWASP: CUSUM). Cannot detect gradual drift.',
      recommendation: 'Add CUSUM behavioral baselines. Add remote kill switch. Add auto-shutdown on anomaly detection.',
    };
  }

  return {
    code, title, status: 'NOT_PROTECTED', evidence,
    summary: 'No kill switch or behavioral monitoring. Rogue agents cannot be detected or stopped.',
    details: 'No behavioral baselines, no drift detection, no remote kill switch, no auto-shutdown, no scope boundaries. If an agent becomes rogue (accumulated drift, misaligned goals, autonomous escalation), there is no way to detect or stop it. OWASP: "Highest-severity risk in the taxonomy."',
    recommendation: 'Implement CUSUM behavioral baselines. Add remote kill switch. Add auto-shutdown. Set scope boundaries.',
  };
}
