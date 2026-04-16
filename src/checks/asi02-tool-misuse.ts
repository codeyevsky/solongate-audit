import type { ScanResult, CheckResult, Evidence } from '../types.js';

// OWASP ASI02: Tool Misuse and Exploitation
// Agent uses legitimate tools in unsafe ways — data exfiltration, over-invoking APIs, deleting data.
// PROTECTED = policy with DENY rules + constraints, actively enforced by proxy
// PARTIAL = some restrictions but incomplete coverage
// NOT_PROTECTED = no tool access restrictions

export function checkToolMisuse(scan: ScanResult): CheckResult {
  const code = 'ASI02';
  const title = 'Tool Misuse';
  const evidence: Evidence[] = [];

  const hasProxy = scan.proxiedCount > 0;
  const hasDeny = scan.denyRules.length > 0;
  const hasConstraints = scan.hasCommandRestrictions || scan.hasFileRestrictions || scan.hasUrlRestrictions || scan.hasPathRestrictions;

  if (scan.policyConfig) {
    evidence.push({ icon: 'found', text: `Policy: ${scan.policyConfig.path}` });
    evidence.push({ icon: 'info', text: `  ${scan.denyRules.length} DENY + ${scan.allowRules.length} ALLOW rules` });

    for (const r of scan.denyRules.slice(0, 5)) {
      const parts: string[] = [];
      if (r.commandConstraints?.denied?.length) parts.push(`commands blocked: ${r.commandConstraints.denied.slice(0, 3).join(', ')}`);
      if (r.filenameConstraints?.denied?.length) parts.push(`files blocked: ${r.filenameConstraints.denied.slice(0, 3).join(', ')}`);
      if (r.urlConstraints?.denied?.length) parts.push(`URLs blocked: ${r.urlConstraints.denied.slice(0, 3).join(', ')}`);
      const desc = r.description ? r.description.slice(0, 50) : `DENY [${r.toolPattern}]`;
      evidence.push({ icon: 'found', text: `  ${desc}` });
      if (parts.length) evidence.push({ icon: 'info', text: `    ${parts.join('; ')}` });
    }
  } else {
    evidence.push({ icon: 'missing', text: 'No tool access policy file (policy.json, etc.)' });
  }

  if (hasProxy) {
    evidence.push({ icon: 'found', text: `Proxy enforces policy on ${scan.proxiedCount} server(s)` });
  } else if (hasDeny) {
    evidence.push({ icon: 'warn', text: 'Policy file exists but no proxy to enforce it' });
  }

  if (scan.dangerousUnprotected.length > 0) {
    evidence.push({ icon: 'warn', text: `Dangerous servers without proxy: ${scan.dangerousUnprotected.join(', ')}` });
  }

  // PROTECTED = DENY rules with granular constraints + proxy enforcement
  if (hasDeny && hasConstraints && hasProxy) {
    return {
      code, title, status: 'PROTECTED', evidence,
      summary: 'Tool access restricted by policy with active enforcement.',
      details: `${scan.denyRules.length} DENY rule(s) with ${[scan.hasCommandRestrictions && 'command', scan.hasFileRestrictions && 'file', scan.hasUrlRestrictions && 'URL', scan.hasPathRestrictions && 'path'].filter(Boolean).join(', ')} constraints actively enforced by proxy. Unauthorized tool operations are blocked before reaching the server.`,
    };
  }

  if (hasDeny || hasProxy) {
    return {
      code, title, status: 'PARTIAL', evidence,
      summary: hasDeny ? 'Policy rules exist but enforcement or coverage is incomplete.' : 'Proxy active but no explicit DENY rules.',
      details: 'Some tool access control exists but gaps remain. Either constraints are missing, proxy is not enforcing, or coverage is incomplete.',
      recommendation: 'Add DENY rules with commandConstraints, filenameConstraints, urlConstraints to policy.json.',
    };
  }

  return {
    code, title, status: 'NOT_PROTECTED', evidence,
    summary: 'No tool access restrictions. Agents can misuse any tool freely.',
    details: 'Agents can delete data, invoke costly APIs, exfiltrate information, or chain tools in unintended ways with no policy enforcement.',
    recommendation: 'Create policy.json with DENY rules and enforce via MCP proxy.',
  };
}
