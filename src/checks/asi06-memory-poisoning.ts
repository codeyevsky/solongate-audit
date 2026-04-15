import type { ScanResult, CheckResult, Evidence } from '../types.js';

// OWASP ASI06: Memory & Context Poisoning
// Malicious data injected into agent's context/memory via tool outputs, RAG, or stored conversations.
// PROTECTED = tool response scanning + context isolation + validation
// PARTIAL = post-tool audit hooks (logs but doesn't block)
// NOT_PROTECTED = tool outputs go directly to agent memory unscanned

export function checkMemoryPoisoning(scan: ScanResult): CheckResult {
  const code = 'ASI06';
  const title = 'Memory Poisoning';
  const evidence: Evidence[] = [];

  // Response scanning requires active analysis of tool outputs
  // Currently: SolonGate proxy has response scanner, but this is a known limitation area
  const hasProxy = scan.proxiedCount > 0;

  // Post-tool hooks (can observe but typically don't block)
  if (scan.hasPostToolHook || scan.hasAuditHook) {
    evidence.push({ icon: 'found', text: 'Post-tool hooks observe tool outputs' });
    evidence.push({ icon: 'warn', text: '  Hooks log responses but typically do not block poisoned content' });
  } else {
    evidence.push({ icon: 'missing', text: 'No post-tool hooks — tool outputs are not reviewed' });
  }

  // File restrictions (limits what can be read into context)
  if (scan.hasFileRestrictions) {
    evidence.push({ icon: 'found', text: 'File access restrictions reduce surface for context poisoning' });
  }

  // URL restrictions (limits what web content enters context)
  if (scan.hasUrlRestrictions) {
    evidence.push({ icon: 'found', text: 'URL restrictions limit external content ingestion' });
  }

  // Critical gaps
  evidence.push({ icon: 'missing', text: 'No tool response content scanning (indirect prompt injection in outputs)' });
  evidence.push({ icon: 'missing', text: 'No RAG input sanitization' });
  evidence.push({ icon: 'missing', text: 'No context isolation between tool results' });

  // Memory poisoning defense requires ACTIVE scanning of tool outputs
  // File/URL restrictions and audit hooks are not memory poisoning defense
  // They reduce surface but don't scan output content for injected instructions
  return {
    code, title, status: 'NOT_PROTECTED', evidence,
    summary: 'Agent memory can be poisoned via tool outputs and external data.',
    details: 'Tool outputs (file contents, web pages, API responses) go directly into agent context without scanning. Attackers can embed hidden instructions in documents, web pages, or database records that manipulate agent behavior.',
    recommendation: 'Implement response scanning for tool outputs. Restrict file/URL access to reduce attack surface.',
  };
}
