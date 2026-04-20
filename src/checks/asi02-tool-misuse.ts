import type { AuditData, CheckResult, Evidence, DeepAnalysis } from '../types.js';

// OWASP ASI02: Tool Misuse and Exploitation
// Analyze logs for dangerous tool usage — sensitive file access, destructive commands, data exfiltration.

// Only truly sensitive files — not project config or normal dev files
const SENSITIVE_FILES = ['.env.production', 'credentials.json', 'id_rsa', 'id_ed25519', '.pem', '/etc/shadow', '/etc/passwd', 'service-account.json', '.npmrc'];
// Only truly dangerous destructive commands — not normal dev cleanup
const DESTRUCTIVE_PATTERNS = [
  /rm\s+-rf\s+[\/~$.]/, // rm -rf on root, home, or current dir
  /rm\s+-rf\s+\*/, // rm -rf *
  /del\s+\/[sf]/i, // del /f or /s on Windows
  /format\s+[a-z]:/i, // format C:
  /drop\s+(table|database)/i,
  /truncate\s+table/i,
];
// Only flag actual exfiltration patterns, not normal curl/wget usage
const EXFIL_PATTERNS = [
  /\bnc\s+-[a-z]*\s+\S+\s+\d+/, // nc connecting to host:port
  /\bncat\s+/, // ncat usage
  />\s*\/dev\/tcp/, // bash /dev/tcp redirect
  /curl\s+.*--upload-file/, // curl upload
  /scp\s+\S+\s+\S+@/, // scp to remote
];
const WILDCARD_QUERIES = ['SELECT *', 'WHERE 1=1', 'WHERE true', 'OR 1=1'];

export function checkToolMisuse(data: AuditData, deep?: DeepAnalysis): CheckResult {
  const code = 'ASI02';
  const title = 'Tool Misuse';
  const evidence: Evidence[] = [];

  let sensitiveAccess = 0;
  let destructiveCmds = 0;
  let exfilAttempts = 0;
  let wildcardQueries = 0;
  const flagged: string[] = [];

  for (const tc of data.sessions.flatMap((s) => s.toolCalls)) {
    const argStr = JSON.stringify(tc.arguments).toLowerCase();
    const toolLower = tc.toolName.toLowerCase();

    // Sensitive file access
    if (toolLower.includes('read') || toolLower.includes('file') || toolLower.includes('cat')) {
      for (const sf of SENSITIVE_FILES) {
        if (argStr.includes(sf.toLowerCase())) {
          sensitiveAccess++;
          if (flagged.length < 5) flagged.push(`${tc.toolName}: accessed ${sf}`);
          break;
        }
      }
    }

    // Destructive commands
    if (toolLower.includes('bash') || toolLower.includes('shell') || toolLower.includes('exec') || toolLower.includes('terminal')) {
      for (const dp of DESTRUCTIVE_PATTERNS) {
        if (dp.test(argStr)) {
          destructiveCmds++;
          if (flagged.length < 5) flagged.push(`${tc.toolName}: destructive command matching ${dp.source.slice(0, 30)}`);
          break;
        }
      }

      // Data exfiltration
      for (const ep of EXFIL_PATTERNS) {
        if (ep.test(argStr)) {
          exfilAttempts++;
          if (flagged.length < 5) flagged.push(`${tc.toolName}: potential exfiltration via ${ep.source.slice(0, 25)}`);
          break;
        }
      }
    }

    // Wildcard DB queries
    if (toolLower.includes('query') || toolLower.includes('sql') || toolLower.includes('db')) {
      for (const wq of WILDCARD_QUERIES) {
        if (argStr.includes(wq.toLowerCase())) {
          wildcardQueries++;
          if (flagged.length < 5) flagged.push(`${tc.toolName}: wildcard query "${wq}"`);
          break;
        }
      }
    }
  }

  // Deep: exfiltration chains + data flow leaks
  if (deep) {
    const exfilChains = deep.chains.filter((c) => c.chainName === 'credential-exfiltration');
    if (exfilChains.length > 0) {
      exfilAttempts += exfilChains.length;
      flagged.push(...exfilChains.slice(0, 2).map((c) =>
        `Chain: ${c.steps.map((s) => s.toolName).join(' \u2192 ')} (${c.description})`
      ));
    }
    if (deep.dataFlowLeaks.length > 0) {
      exfilAttempts += deep.dataFlowLeaks.length;
      for (const leak of deep.dataFlowLeaks.slice(0, 3)) {
        flagged.push(`Data flow: ${leak.sourceToolName} (${leak.dataType}) \u2192 ${leak.sinkToolName}`);
      }
    }
  }

  const totalIssues = sensitiveAccess + destructiveCmds + exfilAttempts + wildcardQueries;

  evidence.push({ icon: 'info', text: `Scanned ${data.totalToolCalls} tool calls for misuse patterns` });

  if (sensitiveAccess > 0) evidence.push({ icon: 'warn', text: `${sensitiveAccess} sensitive file access(es) (.env, credentials, keys)` });
  if (destructiveCmds > 0) evidence.push({ icon: 'warn', text: `${destructiveCmds} destructive command(s) (rm, del, drop, truncate)` });
  if (exfilAttempts > 0) evidence.push({ icon: 'warn', text: `${exfilAttempts} potential data exfiltration attempt(s) (curl, wget, nc)` });
  if (wildcardQueries > 0) evidence.push({ icon: 'warn', text: `${wildcardQueries} wildcard database query(ies) (SELECT *, WHERE 1=1)` });

  for (const f of flagged) {
    evidence.push({ icon: 'warn', text: `  ${f}` });
  }

  if (totalIssues === 0) {
    evidence.push({ icon: 'found', text: 'No tool misuse patterns detected' });
    return {
      code, title, status: 'PROTECTED', evidence,
      summary: 'No tool misuse detected in agent logs.',
      details: `Scanned ${data.totalToolCalls} tool calls. No sensitive file access, destructive commands, exfiltration attempts, or wildcard queries found.`,
    };
  }

  const total = data.totalToolCalls || 1;
  const rate = (totalIssues / total * 100).toFixed(2);

  if (totalIssues / total < 0.01 && exfilAttempts === 0) {
    return {
      code, title, status: 'PARTIAL', evidence,
      summary: `${totalIssues} tool misuse pattern(s) in ${total} calls (${rate}%).`,
      details: 'Low-frequency misuse patterns. May be legitimate development operations. Review flagged calls.',
      recommendation: 'Add policy.json with DENY rules for sensitive files and destructive commands.',
    };
  }

  return {
    code, title, status: 'NOT_PROTECTED', evidence,
    summary: `${totalIssues} tool misuse pattern(s) in ${total} calls (${rate}%).`,
    details: 'Agents accessed sensitive files, ran destructive commands, or attempted data exfiltration. No policy enforcement prevented these actions.',
    recommendation: 'Create policy.json with DENY rules. Enforce via MCP proxy with argument constraints.',
  };
}
