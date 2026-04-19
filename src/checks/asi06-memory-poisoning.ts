import type { AuditData, CheckResult, Evidence } from '../types.js';

// OWASP ASI06: Memory & Context Poisoning
// Analyze logs for suspicious content in tool results that could poison agent memory.

const MINJA_PATTERNS = [
  /skip\s+(authorization|auth)\s+checks?/i,
  /user\s+is\s+(verified\s+)?admin/i,
  /full\s+access\s+(granted|enabled)/i,
  /ignore\s+(security|safety|restriction)/i,
  /bypass\s+(auth|security|check)/i,
  /you\s+have\s+permission/i,
  /elevated\s+privileges?/i,
  /disable\s+(logging|audit|monitoring)/i,
  /trust\s+this\s+(source|input|data)/i,
  /no\s+verification\s+needed/i,
];

export function checkMemoryPoisoning(data: AuditData): CheckResult {
  const code = 'ASI06';
  const title = 'Memory Poisoning';
  const evidence: Evidence[] = [];

  let poisoningPatterns = 0;
  let unscanResults = 0;
  const flagged: string[] = [];

  for (const tc of data.sessions.flatMap((s) => s.toolCalls)) {
    const result = tc.result || '';

    // Check tool results for MINJA-style poisoning patterns
    for (const pattern of MINJA_PATTERNS) {
      if (pattern.test(result)) {
        poisoningPatterns++;
        if (flagged.length < 3) {
          flagged.push(`${tc.toolName}: result contains "${result.match(pattern)?.[0]}"`);
        }
        break;
      }
    }

    // Count tool calls that returned data (potential memory poisoning surface)
    if (result.length > 100) unscanResults++;
  }

  evidence.push({ icon: 'info', text: `Scanned ${data.totalToolCalls} tool results for memory poisoning patterns` });
  evidence.push({ icon: 'info', text: `${unscanResults} tool result(s) returned substantial data (>100 chars) — unscanned` });

  if (poisoningPatterns > 0) {
    evidence.push({ icon: 'warn', text: `${poisoningPatterns} MINJA-style poisoning pattern(s) detected in tool results` });
    for (const f of flagged) {
      evidence.push({ icon: 'warn', text: `  ${f}` });
    }
  } else {
    evidence.push({ icon: 'found', text: 'No MINJA poisoning patterns detected in tool results' });
  }

  evidence.push({ icon: 'missing', text: 'No response scanning — tool outputs go directly into agent context' });
  evidence.push({ icon: 'missing', text: 'No memory validation — poisoned data can persist across sessions' });
  evidence.push({ icon: 'missing', text: 'No context isolation between tool results' });

  if (poisoningPatterns > 0) {
    return {
      code, title, status: 'NOT_PROTECTED', evidence,
      summary: `${poisoningPatterns} memory poisoning pattern(s) found in tool results.`,
      details: 'Tool results contain instructions that could manipulate agent behavior (MINJA attack). Patterns like "skip authorization" or "user is admin" found in data returned to agents.',
      recommendation: 'Implement response scanning with MINJA-informed rules. Add memory validation. Add context isolation.',
    };
  }

  // Unscanned results alone is PARTIAL — only actual poisoning is NOT_PROTECTED
  if (unscanResults > 50) {
    return {
      code, title, status: 'PARTIAL', evidence,
      summary: `${unscanResults} unscanned tool results — no poisoning detected, but no scanning exists.`,
      details: `${unscanResults} tool results with substantial data passed directly to agent context without scanning. No MINJA patterns detected yet, but no scanning exists to catch future attacks.`,
      recommendation: 'Implement response scanning for tool outputs. Add MINJA-informed rules.',
    };
  }

  return {
    code, title, status: 'PARTIAL', evidence,
    summary: 'No poisoning detected, but no scanning exists to prevent it.',
    details: 'No MINJA patterns found in current logs. But tool outputs are not scanned — future attacks would go undetected.',
    recommendation: 'Implement response scanning with MINJA-informed rules. Add memory validation.',
  };
}
