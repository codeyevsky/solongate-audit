import type { ScanResult, CheckResult, Evidence } from '../types.js';

// OWASP ASI08: Cascading Failures
// Failures propagate across multi-agent systems; agents fail open when policy engine unreachable.
// OWASP mitigations: fail-closed SDK (DENY if control plane unreachable),
// spike detection, circuit breakers, timeout enforcement, resource quotas.

export function checkCascadingFailures(scan: ScanResult): CheckResult {
  const code = 'ASI08';
  const title = 'Cascading Failures';
  const evidence: Evidence[] = [];

  // OWASP: Fail-closed behavior — DENY if control plane unreachable
  if (scan.hasFailClosed) {
    evidence.push({ icon: 'found', text: 'Fail-closed mode — returns DENY if policy engine unreachable (OWASP: design principle, not config)' });
  } else {
    evidence.push({ icon: 'missing', text: 'No fail-closed behavior — agents may fail OPEN if policy engine unreachable (OWASP: critical gap)' });
  }

  // OWASP: Spike detection — deny-rate spike indicates cascading failure
  if (scan.hasSpikeDetection) {
    evidence.push({ icon: 'found', text: 'Spike detection — unusual deny-rate increases trigger alerts' });
  } else {
    evidence.push({ icon: 'missing', text: 'No spike detection — cascading failures may go undetected until system-wide impact' });
  }

  // OWASP: Circuit breaker pattern
  if (scan.hasCircuitBreaker) {
    evidence.push({ icon: 'found', text: 'Circuit breaker — stops cascading failures between agents' });
  } else {
    evidence.push({ icon: 'missing', text: 'No circuit breaker pattern — failures propagate freely between agents' });
  }

  // OWASP: Timeout enforcement
  if (scan.hasTimeout) {
    evidence.push({ icon: 'found', text: 'Timeout enforcement on tool calls — prevents infinite hangs' });
  } else {
    evidence.push({ icon: 'missing', text: 'No timeout enforcement — long-running tool calls can hang indefinitely' });
  }

  // Rate limiting
  if (scan.hasRateLimitFlag) {
    evidence.push({ icon: 'found', text: 'Custom rate limiting configured in proxy' });
  } else if (scan.proxiedCount > 0) {
    evidence.push({ icon: 'found', text: 'MCP proxy has default rate limiting (60 req/min per tool)' });
    evidence.push({ icon: 'warn', text: '  Default rate limiting alone does not prevent cascading failures' });
  } else {
    evidence.push({ icon: 'missing', text: 'No rate limiting — agents can make unlimited tool calls' });
  }

  if (scan.rateLimitDeps.length > 0) {
    evidence.push({ icon: 'found', text: `Rate limit library: ${scan.rateLimitDeps.join(', ')}` });
  }

  // Container isolation
  if (scan.hasDockerfile) {
    evidence.push({ icon: 'found', text: 'Docker — failure isolation via container boundaries' });
  } else {
    evidence.push({ icon: 'missing', text: 'No container isolation — failures propagate on shared host' });
  }

  // Error tracking
  if (scan.errorTrackingDeps.length > 0) {
    evidence.push({ icon: 'found', text: `Error tracking: ${scan.errorTrackingDeps.join(', ')}` });
  } else {
    evidence.push({ icon: 'missing', text: 'No error tracking — cascading failures may go undetected' });
  }

  // Resource quotas
  evidence.push({ icon: 'missing', text: 'No resource quotas per agent session' });

  // PROTECTED: fail-closed + spike detection + circuit breaker + timeout
  if (scan.hasFailClosed && (scan.hasSpikeDetection || scan.hasCircuitBreaker) && scan.hasTimeout) {
    return {
      code, title, status: 'PROTECTED', evidence,
      summary: 'Fail-closed design with circuit breakers and timeout enforcement.',
      details: 'System returns DENY when policy engine unreachable (fail-closed). Circuit breakers and spike detection prevent failure propagation. Timeouts prevent infinite hangs.',
    };
  }

  // PARTIAL: some failure mitigation but not fail-closed
  if (scan.hasFailClosed || scan.hasCircuitBreaker || scan.hasTimeout ||
      (scan.hasRateLimitFlag && scan.hasDockerfile && scan.errorTrackingDeps.length > 0)) {
    return {
      code, title, status: 'PARTIAL', evidence,
      summary: 'Some failure mitigation exists but incomplete cascading failure defense.',
      details: scan.hasFailClosed
        ? 'Fail-closed design prevents fail-open. But no circuit breakers or spike detection to catch cascading patterns.'
        : 'Rate limiting, isolation, or error tracking provide some defense. But no fail-closed guarantee — system may allow everything if policy engine goes down.',
      recommendation: 'Enable fail-closed mode. Add circuit breaker. Add timeout enforcement. Add spike detection.',
    };
  }

  return {
    code, title, status: 'NOT_PROTECTED', evidence,
    summary: 'No cascading failure prevention. One failure can take down everything.',
    details: 'No fail-closed design, no circuit breakers, no timeouts, no spike detection. A single agent failure (infinite loop, resource exhaustion, API overload) can cascade and take down the entire system. OWASP: "Fail-closed is a design principle, not a configuration option."',
    recommendation: 'Implement fail-closed mode. Add circuit breakers. Add timeout enforcement. Add spike detection.',
  };
}
