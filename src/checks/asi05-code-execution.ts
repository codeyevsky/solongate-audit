import type { ScanResult, CheckResult, Evidence } from '../types.js';

// OWASP ASI05: Unexpected Code Execution (RCE)
// Agents execute unvetted code, including sandbox escapes and command injection.
// OWASP mitigations: REVIEW decision for code execution tools with human approval,
// route to specific reviewer groups, combine with input scanning, sandboxing.

export function checkCodeExecution(scan: ScanResult): CheckResult {
  const code = 'ASI05';
  const title = 'Code Execution';
  const evidence: Evidence[] = [];

  const hasProxy = scan.proxiedCount > 0;
  const hasInputGuard = hasProxy && !scan.hasNoInputGuardFlag;
  const hasDocker = scan.hasDockerfile;

  // OWASP: REVIEW decision — require human approval for code execution tools
  if (scan.hasReviewDecision) {
    evidence.push({ icon: 'found', text: 'REVIEW decision configured — code execution requires human approval' });
  } else {
    evidence.push({ icon: 'missing', text: 'No REVIEW decision — code execution not routed for human approval (OWASP: highest-friction operation)' });
  }

  // OWASP: Specific restrictions on code exec tools
  if (scan.hasCodeExecRestriction) {
    evidence.push({ icon: 'found', text: 'Code execution tools (shell_exec, run_python, eval_js) explicitly restricted in policy' });
  } else {
    evidence.push({ icon: 'missing', text: 'No specific restrictions on code execution tools in policy' });
  }

  // Command restrictions in policy
  if (scan.hasCommandRestrictions) {
    const cmds = scan.denyRules.flatMap((r) => r.commandConstraints?.denied ?? []);
    evidence.push({ icon: 'found', text: `Command restrictions: ${cmds.slice(0, 5).join(', ')}${cmds.length > 5 ? '...' : ''}` });
  } else {
    evidence.push({ icon: 'missing', text: 'No command restrictions in policy — any shell command allowed' });
  }

  // Input guard (shell injection detection)
  if (hasInputGuard) {
    evidence.push({ icon: 'found', text: 'Input guard catches shell injection patterns (;, |, &, $(), base64 -d, etc.)' });
    evidence.push({ icon: 'warn', text: '  Limitation: blocks known patterns — cannot prevent all code execution' });
  } else {
    evidence.push({ icon: 'missing', text: 'No input guard — shell injection in tool arguments not detected' });
  }

  // Sandbox
  if (hasDocker) {
    evidence.push({ icon: 'found', text: 'Dockerfile present — code can execute in isolated container' });
  } else {
    evidence.push({ icon: 'missing', text: 'No container/sandbox — code executes directly on host system' });
  }

  // Pre-tool hooks
  if (scan.hasPreToolHook) {
    evidence.push({ icon: 'found', text: 'Pre-tool hooks can intercept and review commands before execution' });
  }

  // Dangerous servers without proxy
  const shellServers = scan.servers.filter((s) => s.detectedTools.includes('shell_exec') && !s.proxy);
  if (shellServers.length > 0) {
    evidence.push({ icon: 'warn', text: `Shell-capable servers without proxy: ${shellServers.map((s) => s.name).join(', ')}` });
  }

  // PROTECTED = REVIEW decision + sandbox + restrictions (OWASP: make code exec highest-friction)
  if (scan.hasReviewDecision && hasDocker && (scan.hasCommandRestrictions || hasInputGuard)) {
    return {
      code, title, status: 'PROTECTED', evidence,
      summary: 'Code execution requires human approval and runs in sandbox.',
      details: 'REVIEW decision routes code execution for human approval. Container isolation limits blast radius. Input guard and command restrictions provide defense in depth.',
    };
  }

  // Also PROTECTED without REVIEW if sandbox + restrictions
  if (hasDocker && (scan.hasCommandRestrictions || hasInputGuard)) {
    return {
      code, title, status: 'PROTECTED', evidence,
      summary: 'Code execution sandboxed and restricted.',
      details: 'Container isolation limits blast radius. Command restrictions and/or input guard prevent shell injection. Defense in depth against RCE. Add REVIEW decision for full OWASP compliance.',
    };
  }

  // PARTIAL = some restrictions but no sandbox or human approval
  if (hasInputGuard || scan.hasCommandRestrictions || scan.hasPreToolHook || scan.hasCodeExecRestriction) {
    return {
      code, title, status: 'PARTIAL', evidence,
      summary: 'Some code execution restrictions, but no sandboxing or human approval.',
      details: hasInputGuard
        ? 'Input guard catches known shell injection patterns. But code runs on host — a bypass means full system access. No human approval (REVIEW decision) for code execution.'
        : 'Command restrictions block specific dangerous commands. No sandbox isolation. No human approval gate.',
      recommendation: 'Add Dockerfile for sandbox. Add REVIEW decision for code exec tools. Input guard + sandbox + human approval = OWASP compliant.',
    };
  }

  return {
    code, title, status: 'NOT_PROTECTED', evidence,
    summary: 'No code execution restrictions. Full RCE possible.',
    details: 'Agents can execute arbitrary shell commands, scripts, and code on the host system. No input validation, no command restrictions, no sandboxing, no human approval. OWASP says: make code execution the highest-friction operation.',
    recommendation: 'Add REVIEW decision for code exec tools. Add sandbox (Dockerfile). Add input guard + command restrictions.',
  };
}
