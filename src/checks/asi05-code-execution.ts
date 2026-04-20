import type { AuditData, CheckResult, Evidence, DeepAnalysis } from '../types.js';

// OWASP ASI05: Unexpected Code Execution (RCE)
// Analyze logs for arbitrary code execution — shell commands, eval, script execution.

// Only flag patterns that indicate INJECTION, not normal shell usage
// Normal: `git status && git push`, `cat file | grep pattern` — NOT dangerous
// Dangerous: injection via tool args, not legitimate shell commands
const DANGEROUS_PATTERNS = [
  { pattern: /eval\s*\(/, label: 'eval() — arbitrary code execution' },
  { pattern: /\bexec\s*\(/, label: 'exec() — arbitrary code execution' },
  { pattern: /python\s+-c\s+['"]/, label: 'python -c inline code execution' },
  { pattern: /node\s+-e\s+['"]/, label: 'node -e inline code execution' },
  { pattern: /curl\s+.*\|\s*(ba)?sh/, label: 'curl pipe to shell — remote code execution' },
  { pattern: /wget\s+.*\|\s*(ba)?sh/, label: 'wget pipe to shell — remote code execution' },
  { pattern: /base64\s+-d\s*\|/, label: 'base64 decode piped to execution' },
  { pattern: /powershell\s+-e(ncodedcommand)?/i, label: 'powershell encoded command' },
];

export function checkCodeExecution(data: AuditData, deep?: DeepAnalysis): CheckResult {
  const code = 'ASI05';
  const title = 'Code Execution';
  const evidence: Evidence[] = [];

  let shellCalls = 0;
  let dangerousExec = 0;
  let noSandbox = true;
  const flagged: string[] = [];

  for (const tc of data.sessions.flatMap((s) => s.toolCalls)) {
    const toolLower = tc.toolName.toLowerCase();
    const argStr = JSON.stringify(tc.arguments);

    // Count shell/exec calls
    if (toolLower.includes('bash') || toolLower.includes('shell') || toolLower.includes('exec') || toolLower.includes('terminal')) {
      shellCalls++;

      // Check for container/sandbox indicators
      if (argStr.includes('docker ') || argStr.includes('sandbox') || argStr.includes('container')) {
        noSandbox = false;
      }

      // Check for dangerous patterns
      for (const { pattern, label } of DANGEROUS_PATTERNS) {
        if (pattern.test(argStr)) {
          dangerousExec++;
          if (flagged.length < 5) flagged.push(`${tc.toolName}: ${label}`);
          break;
        }
      }
    }
  }

  evidence.push({ icon: 'info', text: `${shellCalls} shell/exec call(s) found in ${data.sessions.length} session(s)` });

  if (shellCalls === 0) {
    evidence.push({ icon: 'found', text: 'No shell execution calls detected in logs' });
    return {
      code, title, status: 'PROTECTED', evidence,
      summary: 'No code execution detected in agent logs.',
      details: 'No shell commands, eval, or script execution found in any session.',
    };
  }

  if (dangerousExec > 0) {
    evidence.push({ icon: 'warn', text: `${dangerousExec} dangerous execution pattern(s) detected` });
    for (const f of flagged) {
      evidence.push({ icon: 'warn', text: `  ${f}` });
    }
  } else {
    evidence.push({ icon: 'found', text: 'No dangerous execution patterns (injection, chaining) detected' });
  }

  if (noSandbox) {
    evidence.push({ icon: 'missing', text: 'No sandbox/container execution detected — all commands run on host' });
  } else {
    evidence.push({ icon: 'found', text: 'Some commands executed in container/sandbox environment' });
  }

  // Deep: execution chain detection
  if (deep) {
    const execChains = deep.chains.filter((c) =>
      c.chainName === 'privilege-escalation-sequence' || c.chainName === 'read-exec-chain'
    );
    if (execChains.length > 0) {
      evidence.push({ icon: 'warn', text: `${execChains.length} execution chain(s): file content flowing into shell commands` });
      for (const chain of execChains.slice(0, 3)) {
        evidence.push({ icon: 'warn', text: `  ${chain.steps.map((s) => s.toolName).join(' \u2192 ')}` });
      }
      dangerousExec += execChains.length;
    }
  }

  evidence.push({ icon: 'missing', text: 'No REVIEW decision — code execution not routed for human approval' });

  if (dangerousExec === 0 && !noSandbox) {
    return {
      code, title, status: 'PROTECTED', evidence,
      summary: 'Shell calls detected but executed in sandbox with no dangerous patterns.',
      details: `${shellCalls} shell calls found. No command injection patterns. Container isolation detected.`,
    };
  }

  if (dangerousExec === 0) {
    return {
      code, title, status: 'PARTIAL', evidence,
      summary: `${shellCalls} shell calls — no injection patterns, but no sandbox.`,
      details: 'Shell commands were executed on the host system without container isolation. No command injection patterns detected, but any bypass means full system access.',
      recommendation: 'Add REVIEW decision for code exec tools. Add Dockerfile for sandbox. Add input guard.',
    };
  }

  const dangerRate = shellCalls > 0 ? (dangerousExec / shellCalls * 100).toFixed(2) : '0';

  if (dangerousExec / (shellCalls || 1) < 0.005) {
    return {
      code, title, status: 'PARTIAL', evidence,
      summary: `${dangerousExec} dangerous pattern(s) in ${shellCalls} shell calls (${dangerRate}%).`,
      details: 'Very low-frequency dangerous patterns. Likely legitimate usage. No sandbox or human approval.',
      recommendation: 'Add REVIEW decision for code exec. Add sandbox (Dockerfile). Add input guard.',
    };
  }

  return {
    code, title, status: 'NOT_PROTECTED', evidence,
    summary: `${dangerousExec} dangerous pattern(s) in ${shellCalls} shell calls (${dangerRate}%).`,
    details: 'Agents executed shell commands with dangerous patterns (command chaining, injection, eval). No sandbox, no human approval. Full RCE possible.',
    recommendation: 'Add REVIEW decision for code exec. Add sandbox (Dockerfile). Add input guard + command restrictions.',
  };
}
