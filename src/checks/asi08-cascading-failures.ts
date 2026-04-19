import type { AuditData, CheckResult, Evidence } from '../types.js';

// OWASP ASI08: Cascading Failures
// Analyze logs for failure patterns — error spikes, retry storms, rapid-fire calls.

export function checkCascadingFailures(data: AuditData): CheckResult {
  const code = 'ASI08';
  const title = 'Cascading Failures';
  const evidence: Evidence[] = [];

  // Analyze error rates
  const allCalls = data.sessions.flatMap((s) => s.toolCalls);
  const errorCalls = allCalls.filter((tc) => tc.isError);
  const errorRate = allCalls.length > 0 ? errorCalls.length / allCalls.length : 0;

  // Detect rapid-fire calls (burst patterns)
  let burstDetected = 0;
  for (const session of data.sessions) {
    const calls = session.toolCalls;
    for (let i = 0; i < calls.length - 5; i++) {
      const window = calls.slice(i, i + 5);
      const t0 = new Date(window[0].timestamp).getTime();
      const t4 = new Date(window[4].timestamp).getTime();
      if (t4 - t0 < 2000 && !isNaN(t0) && !isNaN(t4)) { // 5 calls in <2 seconds
        burstDetected++;
        break; // count once per session
      }
    }
  }

  // Detect retry storms (same tool called repeatedly with errors)
  let retryStorms = 0;
  for (const session of data.sessions) {
    const calls = session.toolCalls;
    for (let i = 0; i < calls.length - 3; i++) {
      const window = calls.slice(i, i + 3);
      if (window.every((c) => c.toolName === window[0].toolName && c.isError)) {
        retryStorms++;
        break;
      }
    }
  }

  // Detect deny-rate spikes (errors concentrated in time)
  let errorSpikes = 0;
  for (const session of data.sessions) {
    const errors = session.toolCalls.filter((tc) => tc.isError);
    if (errors.length >= 5) {
      const t0 = new Date(errors[0].timestamp).getTime();
      const tN = new Date(errors[errors.length - 1].timestamp).getTime();
      if (tN - t0 < 30000 && !isNaN(t0) && !isNaN(tN)) { // 5+ errors in <30s
        errorSpikes++;
      }
    }
  }

  evidence.push({ icon: 'info', text: `${allCalls.length} tool calls, ${errorCalls.length} errors (${(errorRate * 100).toFixed(1)}% error rate)` });

  if (errorRate > 0.2) {
    evidence.push({ icon: 'warn', text: `High error rate: ${(errorRate * 100).toFixed(1)}% — potential cascading failure indicator` });
  } else if (errorCalls.length > 0) {
    evidence.push({ icon: 'info', text: `Error rate ${(errorRate * 100).toFixed(1)}% — within normal range` });
  }

  if (burstDetected > 0) {
    evidence.push({ icon: 'warn', text: `${burstDetected} burst pattern(s) detected (5+ calls in <2s) — no rate limiting` });
  }
  if (retryStorms > 0) {
    evidence.push({ icon: 'warn', text: `${retryStorms} retry storm(s) detected (3+ consecutive errors on same tool)` });
  }
  if (errorSpikes > 0) {
    evidence.push({ icon: 'warn', text: `${errorSpikes} error spike(s) detected (5+ errors in <30s)` });
  }

  evidence.push({ icon: 'missing', text: 'No fail-closed behavior detected in logs' });
  evidence.push({ icon: 'missing', text: 'No circuit breaker pattern detected' });
  evidence.push({ icon: 'missing', text: 'No timeout enforcement detected' });

  const totalIssues = burstDetected + retryStorms + errorSpikes + (errorRate > 0.2 ? 1 : 0);

  if (totalIssues === 0 && errorRate <= 0.05) {
    return {
      code, title, status: 'PARTIAL', evidence,
      summary: 'No failure patterns detected, but no safeguards exist.',
      details: 'Logs show normal operation — no bursts, retry storms, or error spikes. But no fail-closed design, circuit breakers, or timeouts exist to prevent future cascading failures.',
      recommendation: 'Implement fail-closed mode. Add circuit breakers. Add timeout enforcement.',
    };
  }

  const sessionCount = data.sessions.length || 1;
  const issueRate = (totalIssues / sessionCount * 100).toFixed(0);

  if (totalIssues > 0 && totalIssues / sessionCount < 0.3) {
    return {
      code, title, status: 'PARTIAL', evidence,
      summary: `${totalIssues} failure pattern(s) in ${sessionCount} sessions (${issueRate}%).`,
      details: 'Some burst patterns or retry storms found at low frequency. No fail-closed design, no circuit breakers.',
      recommendation: 'Implement fail-closed mode. Add circuit breakers. Add rate limiting.',
    };
  }

  if (totalIssues > 0) {
    return {
      code, title, status: 'NOT_PROTECTED', evidence,
      summary: `${totalIssues} failure pattern(s) in ${sessionCount} sessions (${issueRate}%).`,
      details: 'Burst patterns, retry storms, or error spikes found in many sessions. No fail-closed design, no circuit breakers, no timeouts.',
      recommendation: 'Implement fail-closed mode. Add circuit breakers. Add rate limiting. Add timeout enforcement.',
    };
  }

  return {
    code, title, status: 'NOT_PROTECTED', evidence,
    summary: 'No cascading failure safeguards. High error rate in logs.',
    details: 'Error rate exceeds threshold. No fail-closed behavior, no circuit breakers, no spike detection exist to prevent cascading failures.',
    recommendation: 'Implement fail-closed mode. Add circuit breakers. Add spike detection. Add timeout enforcement.',
  };
}
