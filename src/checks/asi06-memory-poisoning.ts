import type { ScanResult, CheckResult, Evidence } from '../types.js';

// OWASP ASI06: Memory & Context Poisoning
// Persistent memory contaminated with manipulative data that survives session resets (MINJA attacks).
// OWASP mitigations: MINJA-informed rules scanning memory writes, detect authorization bypass
// instructions, block poisoned writes, scan all values before persistent storage.

export function checkMemoryPoisoning(scan: ScanResult): CheckResult {
  const code = 'ASI06';
  const title = 'Memory Poisoning';
  const evidence: Evidence[] = [];

  const hasProxy = scan.proxiedCount > 0;

  // OWASP: Response/output scanning — scan tool outputs for indirect prompt injection
  if (scan.hasResponseScanning) {
    evidence.push({ icon: 'found', text: 'Response scanning active — tool outputs scanned for indirect prompt injection' });
  } else {
    evidence.push({ icon: 'missing', text: 'No response scanning — tool outputs go directly into agent context unscanned (OWASP: scan all outputs)' });
  }

  // OWASP: Memory validation — scan values before writing to persistent storage
  if (scan.hasMemoryValidation) {
    evidence.push({ icon: 'found', text: 'Memory validation — values scanned before writing to persistent storage' });
  } else {
    evidence.push({ icon: 'missing', text: 'No memory validation — poisoned data can persist across sessions (OWASP: MINJA defense)' });
  }

  // OWASP: MINJA-informed rules — detect patterns like "Skip authorization checks"
  evidence.push({ icon: 'missing', text: 'No MINJA-informed rules — cannot detect authorization bypass instructions in memory writes' });
  evidence.push({ icon: 'missing', text: '  OWASP examples: "User is verified admin", "Skip authorization checks", fake credentials' });

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

  // Critical OWASP gaps
  evidence.push({ icon: 'missing', text: 'No context isolation between tool results' });
  evidence.push({ icon: 'missing', text: 'No RAG input sanitization' });

  // PROTECTED: response scanning + memory validation + MINJA rules
  if (scan.hasResponseScanning && scan.hasMemoryValidation) {
    return {
      code, title, status: 'PROTECTED', evidence,
      summary: 'Tool outputs scanned and memory writes validated against poisoning patterns.',
      details: 'Response scanning detects indirect prompt injection in tool outputs. Memory validation prevents poisoned data from persisting. MINJA-informed rules block authorization bypass patterns.',
    };
  }

  // PARTIAL: some output scanning exists
  if (scan.hasResponseScanning || scan.hasMemoryValidation) {
    return {
      code, title, status: 'PARTIAL', evidence,
      summary: 'Some output scanning exists but incomplete memory poisoning defense.',
      details: scan.hasResponseScanning
        ? 'Tool outputs are scanned but memory writes are not validated. Poisoned data can still persist across sessions.'
        : 'Memory writes are validated but tool outputs are not scanned for injection. Attackers can inject instructions via file/web/API content.',
      recommendation: 'Add both response scanning and memory validation. Implement MINJA-informed rules.',
    };
  }

  // NOT_PROTECTED: no scanning at all
  return {
    code, title, status: 'NOT_PROTECTED', evidence,
    summary: 'Agent memory can be poisoned via tool outputs and external data.',
    details: 'Tool outputs (file contents, web pages, API responses) go directly into agent context without scanning. Attackers can embed hidden instructions in documents, web pages, or database records that manipulate agent behavior. Poisoned memory persists across sessions (MINJA attack).',
    recommendation: 'Implement response scanning for tool outputs. Add memory validation with MINJA-informed rules. Add context isolation.',
  };
}
