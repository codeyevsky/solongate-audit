import type { ScanResult, CheckResult, Evidence } from '../types.js';

// OWASP ASI01: Agent Goal Hijack
// Attackers manipulate agent objectives via prompt injection, deceptive tool outputs, poisoned data.
// PROTECTED = semantic-level detection + input validation + policy enforcement
// PARTIAL = basic pattern-based prompt injection detection (catches common attacks, not novel ones)
// NOT_PROTECTED = no input validation at all

export function checkGoalHijacking(scan: ScanResult): CheckResult {
  const code = 'ASI01';
  const title = 'Goal Hijacking';
  const evidence: Evidence[] = [];

  const hasProxy = scan.proxiedCount > 0;
  const hasInputGuard = hasProxy && !scan.hasNoInputGuardFlag;
  const hasAiJudge = scan.hasAiJudgeFlag;
  const hasPolicy = scan.denyRules.length > 0;

  if (hasProxy) {
    evidence.push({ icon: 'found', text: `MCP proxy on ${scan.proxiedCount} server(s) — input validation layer` });
  } else {
    evidence.push({ icon: 'missing', text: 'No MCP proxy — tool call arguments are not validated' });
  }

  if (hasInputGuard) {
    evidence.push({ icon: 'found', text: 'Input guard active — catches common prompt injection patterns' });
    evidence.push({ icon: 'info', text: '  Detects: delimiter injection, role hijacking, jailbreak keywords' });
    evidence.push({ icon: 'warn', text: '  Limitation: pattern-based only — novel/obfuscated attacks can bypass' });
  } else if (scan.hasNoInputGuardFlag) {
    evidence.push({ icon: 'warn', text: 'Input guard DISABLED (--no-input-guard flag)' });
  }

  if (hasAiJudge) {
    evidence.push({ icon: 'found', text: 'AI Judge enabled — semantic intent analysis for novel attacks' });
  } else {
    evidence.push({ icon: 'missing', text: 'No semantic analysis (AI Judge) — only rule-based detection' });
  }

  if (scan.hasPreToolHook) {
    evidence.push({ icon: 'found', text: 'Pre-tool hooks — can validate/block before tool execution' });
  }

  if (hasPolicy) {
    evidence.push({ icon: 'found', text: `${scan.denyRules.length} DENY rule(s) limit damage even if goal is hijacked` });
  }

  if (scan.unprotectedCount > 0) {
    evidence.push({ icon: 'warn', text: `${scan.unprotectedCount} server(s) without proxy — no input validation on those` });
  }

  // PROTECTED requires semantic analysis (AI Judge) + input guard + policy
  // Just having input guard = PARTIAL (catches known patterns, not novel attacks)
  if (hasInputGuard && hasAiJudge && hasPolicy) {
    return {
      code, title, status: 'PROTECTED', evidence,
      summary: 'Multi-layer prompt injection defense with semantic analysis.',
      details: 'Input guard catches known patterns, AI Judge analyzes intent semantically, and policy rules limit blast radius. Novel attacks are detected at the semantic level.',
    };
  }

  if (hasInputGuard || scan.hasPreToolHook || scan.hasGuardHook) {
    return {
      code, title, status: 'PARTIAL', evidence,
      summary: 'Prompt injection detection catches common attacks, not novel ones.',
      details: 'Rule-based prompt injection detection catches known attack patterns (delimiter injection, role hijacking, encoding tricks). But novel/obfuscated attacks can bypass pattern matching. No semantic-level goal verification.',
      recommendation: 'Enable AI Judge (--ai-judge) for semantic-level prompt injection analysis.',
    };
  }

  return {
    code, title, status: 'NOT_PROTECTED', evidence,
    summary: 'No prompt injection defense. Agent goals can be hijacked via malicious input.',
    details: 'Attackers can override agent goals through prompt injection in documents, web pages, emails, or tool outputs. No input validation or intent verification exists.',
    recommendation: 'Add MCP proxy with input guard for prompt injection detection. → npx solongate init',
  };
}
