import type { ScanResult, CheckResult, Evidence } from '../types.js';

// OWASP ASI08: Cascading Failures
// One agent failure propagates across the system — resource exhaustion, infinite loops, chain reactions.
// PROTECTED = rate limiting + circuit breakers + timeout enforcement + isolation
// PARTIAL = basic rate limiting exists
// NOT_PROTECTED = no failure isolation at all

export function checkCascadingFailures(scan: ScanResult): CheckResult {
  const code = 'ASI08';
  const title = 'Cascading Failures';
  const evidence: Evidence[] = [];

  // Rate limiting
  if (scan.hasRateLimitFlag) {
    evidence.push({ icon: 'found', text: 'Custom rate limiting configured in proxy' });
  } else if (scan.proxiedCount > 0) {
    evidence.push({ icon: 'found', text: 'MCP proxy has default rate limiting (60 req/min per tool)' });
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

  // Critical gaps
  evidence.push({ icon: 'missing', text: 'No circuit breaker pattern for agent-to-agent calls' });
  evidence.push({ icon: 'missing', text: 'No timeout enforcement on long-running tool calls' });
  evidence.push({ icon: 'missing', text: 'No resource quotas per agent session' });

  // Cascading failure prevention requires multiple layers — rate limiting alone is not enough
  if (scan.hasRateLimitFlag && scan.hasDockerfile && scan.errorTrackingDeps.length > 0) {
    return {
      code, title, status: 'PARTIAL', evidence,
      summary: 'Rate limiting + container isolation, but no circuit breakers or timeouts.',
      details: 'Rate limiting prevents burst abuse. Container isolation limits blast radius. Error tracking detects failures. But no circuit breaker pattern, no timeout enforcement, no resource quotas.',
      recommendation: 'Implement circuit breaker for inter-agent calls. Add timeout enforcement per tool call.',
    };
  }

  // Default proxy rate limiting alone is NOT enough for cascading failure prevention
  // It only limits per-tool call frequency — no circuit breakers, no timeouts, no isolation

  return {
    code, title, status: 'NOT_PROTECTED', evidence,
    summary: 'No cascading failure prevention. One failure can take down everything.',
    details: 'No rate limiting, no circuit breakers, no timeouts, no isolation. A single agent failure (infinite loop, resource exhaustion, API overload) can cascade and take down the entire system.',
    recommendation: 'Add MCP proxy with rate limiting. Add Docker for isolation. Add error tracking.',
  };
}
