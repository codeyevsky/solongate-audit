import type { ScanResult, CheckResult, Evidence } from '../types.js';

// OWASP ASI05: Unexpected Code Execution (RCE)
// Agent executes arbitrary code — shell commands, scripts, eval() — via injection or misuse.
// PROTECTED = sandboxed execution + command restrictions + input guard
// PARTIAL = input guard catches shell injection OR command restrictions exist (but no sandbox)
// NOT_PROTECTED = no restrictions on code execution

export function checkCodeExecution(scan: ScanResult): CheckResult {
  const code = 'ASI05';
  const title = 'Code Execution';
  const evidence: Evidence[] = [];

  const hasProxy = scan.proxiedCount > 0;
  const hasInputGuard = hasProxy && !scan.hasNoInputGuardFlag;
  const hasDocker = scan.hasDockerfile;

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

  // PROTECTED = sandbox + restrictions (defense in depth)
  if (hasDocker && (scan.hasCommandRestrictions || hasInputGuard)) {
    return {
      code, title, status: 'PROTECTED', evidence,
      summary: 'Code execution sandboxed and restricted.',
      details: 'Container isolation limits blast radius. Command restrictions and/or input guard prevent shell injection. Defense in depth against RCE.',
    };
  }

  // PARTIAL = either input guard catches injection OR command restrictions exist
  if (hasInputGuard || scan.hasCommandRestrictions || scan.hasPreToolHook) {
    return {
      code, title, status: 'PARTIAL', evidence,
      summary: 'Some code execution restrictions, but no sandboxing.',
      details: hasInputGuard
        ? 'Input guard catches known shell injection patterns (command separators, encoding tricks). But code still runs on host — a bypass means full system access.'
        : 'Command restrictions block specific dangerous commands, but execution happens on the host system without isolation.',
      recommendation: 'Add Dockerfile for sandboxed execution. Input guard + sandbox = defense in depth.',
    };
  }

  return {
    code, title, status: 'NOT_PROTECTED', evidence,
    summary: 'No code execution restrictions. Full RCE possible.',
    details: 'Agents can execute arbitrary shell commands, scripts, and code on the host system. No input validation, no command restrictions, no sandboxing. This is the highest-risk vulnerability.',
    recommendation: 'Add MCP proxy with input guard + command restrictions in policy.json + Dockerfile for sandboxing.',
  };
}
