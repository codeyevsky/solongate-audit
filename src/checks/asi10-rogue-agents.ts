import type { AuditData, CheckResult, Evidence } from '../types.js';

// OWASP ASI10: Rogue Agents
// Analyze logs for behavioral drift — sustained pattern changes, scope escalation, anomalous volumes.

export function checkRogueAgents(data: AuditData): CheckResult {
  const code = 'ASI10';
  const title = 'Rogue Agents';
  const evidence: Evidence[] = [];

  // Analyze per-session behavior for drift
  let scopeEscalation = 0;
  let volumeSpikes = 0;
  let unusualTools = 0;

  // Calculate average tool calls per session
  const avgCallsPerSession = data.sessions.length > 0
    ? data.totalToolCalls / data.sessions.length
    : 0;

  for (const session of data.sessions) {
    // Volume spike: session with 3x+ average tool calls
    if (session.toolCalls.length > avgCallsPerSession * 3 && avgCallsPerSession > 10) {
      volumeSpikes++;
    }

    // Scope escalation: session that starts with reads and escalates to writes/exec
    const calls = session.toolCalls;
    const firstHalf = calls.slice(0, Math.floor(calls.length / 2));
    const secondHalf = calls.slice(Math.floor(calls.length / 2));

    const firstDangerous = firstHalf.filter((c) => {
      const t = c.toolName.toLowerCase();
      return t.includes('exec') || t.includes('bash') || t.includes('shell') || t.includes('delete');
    }).length;

    const secondDangerous = secondHalf.filter((c) => {
      const t = c.toolName.toLowerCase();
      return t.includes('exec') || t.includes('bash') || t.includes('shell') || t.includes('delete');
    }).length;

    if (secondHalf.length > 5 && secondDangerous > firstDangerous * 2 && secondDangerous > 3) {
      scopeEscalation++;
    }

    // Unusual tool usage (tools used only in one session)
    const toolSet = new Set(calls.map((c) => c.toolName));
    for (const tool of toolSet) {
      const otherSessions = data.sessions.filter((s) => s.id !== session.id);
      const usedElsewhere = otherSessions.some((s) => s.toolCalls.some((tc) => tc.toolName === tool));
      if (!usedElsewhere && calls.filter((c) => c.toolName === tool).length > 5) {
        unusualTools++;
      }
    }
  }

  evidence.push({ icon: 'info', text: `${data.sessions.length} session(s), avg ${Math.round(avgCallsPerSession)} calls/session` });

  if (volumeSpikes > 0) {
    evidence.push({ icon: 'warn', text: `${volumeSpikes} session(s) with 3x+ volume spike (anomalous activity)` });
  }

  if (scopeEscalation > 0) {
    evidence.push({ icon: 'warn', text: `${scopeEscalation} session(s) show scope escalation (reads → exec/delete)` });
  }

  if (unusualTools > 0) {
    evidence.push({ icon: 'warn', text: `${unusualTools} unusual tool usage pattern(s) (tools only used in one session)` });
  }

  evidence.push({ icon: 'missing', text: 'No CUSUM behavioral drift detection — no per-agent baselines' });
  evidence.push({ icon: 'missing', text: 'No remote kill switch — cannot instantly stop a rogue agent' });
  evidence.push({ icon: 'missing', text: 'No auto-shutdown on anomalous behavior' });
  evidence.push({ icon: 'missing', text: 'No drift thresholds (denyRateIncrease: 2.0x, actionVolumeSpike: 3.0x)' });
  evidence.push({ icon: 'missing', text: 'No scope boundaries — agents can self-escalate' });

  const totalAnomalies = volumeSpikes + scopeEscalation;

  const sessionCount = data.sessions.length || 1;
  const anomalyRate = (totalAnomalies / sessionCount * 100).toFixed(0);

  if (totalAnomalies > 0 && totalAnomalies / sessionCount < 0.2) {
    return {
      code, title, status: 'PARTIAL', evidence,
      summary: `${totalAnomalies} anomaly(ies) in ${sessionCount} sessions (${anomalyRate}%) — no kill switch.`,
      details: 'Some anomalous patterns at low frequency. No CUSUM baselines or kill switch, but current risk is moderate.',
      recommendation: 'Implement CUSUM behavioral baselines. Add remote kill switch. Add auto-shutdown on anomaly.',
    };
  }

  if (totalAnomalies > 0) {
    return {
      code, title, status: 'NOT_PROTECTED', evidence,
      summary: `${totalAnomalies} anomaly(ies) in ${sessionCount} sessions (${anomalyRate}%) — no kill switch.`,
      details: 'Volume spikes or scope escalation patterns found in many sessions. No CUSUM baselines to detect drift. No remote kill switch or auto-shutdown.',
      recommendation: 'Implement CUSUM behavioral baselines. Add remote kill switch. Add auto-shutdown on anomaly.',
    };
  }

  return {
    code, title, status: 'NOT_PROTECTED', evidence,
    summary: 'No behavioral monitoring or kill switch. Rogue agents undetectable.',
    details: 'No behavioral baselines, no drift detection, no kill switch. If an agent becomes rogue, there is no way to detect or stop it.',
    recommendation: 'Implement CUSUM behavioral baselines. Add remote kill switch. Add auto-shutdown. Set scope boundaries.',
  };
}
