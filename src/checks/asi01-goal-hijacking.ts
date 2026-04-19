import type { AuditData, CheckResult, Evidence } from '../types.js';

// OWASP ASI01: Agent Goal Hijacking
// Analyze logs for signs of prompt injection in tool arguments and results.

const INJECTION_PATTERNS = [
  /ignore\s+(previous|above|all)\s+(instructions|rules)/i,
  /you\s+are\s+now\s+(a|an|the)/i,
  /\<\/?system\s*>/i,
  /\[\s*INST\s*\]/i,
  /act\s+as\s+(a|an|if)\s+you/i,
  /forget\s+(everything|all|your)\s+(instructions|rules|context)/i,
  /override\s+(your|the|all)\s+(instructions|rules|safety)/i,
  /new\s+instructions?\s*:/i,
  /do\s+not\s+follow\s+(any|your|the)\s+(previous|original)/i,
  /disregard\s+(all|any|your)\s+(previous|prior|original)/i,
];

export function checkGoalHijacking(data: AuditData): CheckResult {
  const code = 'ASI01';
  const title = 'Goal Hijacking';
  const evidence: Evidence[] = [];

  let injectionAttempts = 0;
  const examples: string[] = [];

  for (const tc of data.sessions.flatMap((s) => s.toolCalls)) {
    const argStr = JSON.stringify(tc.arguments);
    const resultStr = tc.result || '';

    // Check tool arguments for injection patterns
    for (const pattern of INJECTION_PATTERNS) {
      if (pattern.test(argStr)) {
        injectionAttempts++;
        if (examples.length < 3) {
          examples.push(`${tc.toolName}: arg matches ${pattern.source.slice(0, 30)}`);
        }
        break;
      }
    }

    // Check tool results for injection (indirect prompt injection)
    for (const pattern of INJECTION_PATTERNS) {
      if (pattern.test(resultStr)) {
        injectionAttempts++;
        if (examples.length < 3) {
          examples.push(`${tc.toolName}: result contains injection pattern`);
        }
        break;
      }
    }
  }

  evidence.push({ icon: 'info', text: `Scanned ${data.totalToolCalls} tool calls for prompt injection patterns` });

  if (injectionAttempts === 0) {
    evidence.push({ icon: 'found', text: 'No prompt injection patterns detected in tool calls or results' });
  } else {
    evidence.push({ icon: 'warn', text: `${injectionAttempts} potential prompt injection pattern(s) detected` });
    for (const ex of examples) {
      evidence.push({ icon: 'warn', text: `  ${ex}` });
    }
  }

  // Check if any tool results contain encoded payloads
  let encodedPayloads = 0;
  for (const tc of data.sessions.flatMap((s) => s.toolCalls)) {
    const r = tc.result || '';
    if (/[A-Za-z0-9+/]{50,}={0,2}/.test(r) && /base64|decode|eval/i.test(r)) {
      encodedPayloads++;
    }
  }
  if (encodedPayloads > 0) {
    evidence.push({ icon: 'warn', text: `${encodedPayloads} tool result(s) contain encoded payloads (potential obfuscated injection)` });
  }

  if (injectionAttempts === 0 && encodedPayloads === 0) {
    return {
      code, title, status: 'PROTECTED', evidence,
      summary: 'No prompt injection patterns found in agent logs.',
      details: `Scanned ${data.totalToolCalls} tool calls. No known injection patterns (delimiter injection, role hijacking, encoded payloads) detected in arguments or results.`,
    };
  }

  const total = data.totalToolCalls || 1;
  const rate = ((injectionAttempts + encodedPayloads) / total * 100).toFixed(2);

  if ((injectionAttempts + encodedPayloads) / total < 0.005) {
    return {
      code, title, status: 'PARTIAL', evidence,
      summary: `${injectionAttempts} potential injection pattern(s) in ${total} calls (${rate}%).`,
      details: 'Low-frequency injection patterns found. Could be false positives or minor attempts. Review the flagged calls.',
      recommendation: 'Enable input guard on MCP proxy to block injection patterns before tool execution.',
    };
  }

  return {
    code, title, status: 'NOT_PROTECTED', evidence,
    summary: `${injectionAttempts} prompt injection patterns in ${total} calls (${rate}%).`,
    details: 'Injection patterns found in tool arguments or results. Agents may have processed malicious instructions from external content.',
    recommendation: 'Enable input guard + AI Judge for semantic prompt injection analysis.',
  };
}
