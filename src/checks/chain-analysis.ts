import type { ToolCall, SessionInfo, ChainMatch } from '../types.js';

// ── Tool classification ──

function isFileRead(tc: ToolCall): boolean {
  const t = tc.toolName.toLowerCase();
  return t.includes('read') || t.includes('cat') || t.includes('grep') || t.includes('glob');
}

function isFileWrite(tc: ToolCall): boolean {
  const t = tc.toolName.toLowerCase();
  return t.includes('write') || t.includes('edit');
}

function isShellExec(tc: ToolCall): boolean {
  const t = tc.toolName.toLowerCase();
  return t.includes('bash') || t.includes('shell') || t.includes('exec') || t.includes('terminal');
}

function isNetworkCall(tc: ToolCall): boolean {
  const t = tc.toolName.toLowerCase();
  const argStr = JSON.stringify(tc.arguments).toLowerCase();
  return t.includes('web') || t.includes('fetch') || t.includes('navigate') ||
    (isShellExec(tc) && (argStr.includes('curl ') || argStr.includes('wget ') ||
     argStr.includes('nc ') || argStr.includes('scp ')));
}

function isPrivilegeEscalation(tc: ToolCall): boolean {
  if (!isShellExec(tc)) return false;
  const argStr = JSON.stringify(tc.arguments).toLowerCase();
  return /\bsudo\b/.test(argStr) || /\bchmod\b/.test(argStr) || /\bchown\b/.test(argStr) ||
    /\brunas\b/.test(argStr);
}

function readsSensitiveFile(tc: ToolCall): boolean {
  const argStr = JSON.stringify(tc.arguments).toLowerCase();
  return /\.env(?:\b|\.production|\.local|\.staging)/.test(argStr) ||
    argStr.includes('credentials') || argStr.includes('id_rsa') ||
    argStr.includes('id_ed25519') || argStr.includes('.pem') ||
    argStr.includes('/etc/shadow') || argStr.includes('service-account');
}

function extractSummary(tc: ToolCall): string {
  const args = tc.arguments;
  return String(args.command || args.file_path || args.path || args.url ||
    JSON.stringify(args).slice(0, 60));
}

// ── Chain patterns ──

interface ChainPattern {
  name: string;
  severity: 'high' | 'medium' | 'low';
  description: string;
  steps: ((tc: ToolCall) => boolean)[];
  maxGap: number;
  requireContentOverlap?: boolean;
}

const CHAIN_PATTERNS: ChainPattern[] = [
  {
    name: 'credential-exfiltration',
    severity: 'high',
    description: 'Credential file read followed by network call',
    steps: [readsSensitiveFile, isNetworkCall],
    maxGap: 10,
  },
  {
    name: 'cross-contamination',
    severity: 'medium',
    description: 'File read followed by file write containing read content',
    steps: [isFileRead, isFileWrite],
    maxGap: 5,
    requireContentOverlap: true,
  },
  {
    name: 'privilege-escalation-sequence',
    severity: 'high',
    description: 'Normal read followed by privilege escalation then execution',
    steps: [isFileRead, isPrivilegeEscalation, isShellExec],
    maxGap: 8,
  },
  {
    name: 'read-exec-chain',
    severity: 'medium',
    description: 'File read followed by shell exec using read content',
    steps: [
      (tc) => isFileRead(tc) && !readsSensitiveFile(tc),
      (tc) => isShellExec(tc) && !isPrivilegeEscalation(tc),
    ],
    maxGap: 3,
    requireContentOverlap: true,
  },
];

// ── Content overlap detection ──

function hasContentOverlap(source: ToolCall, sink: ToolCall): boolean {
  const sourceResult = source.result || '';
  if (sourceResult.length < 20) return false;
  const sinkArgs = JSON.stringify(sink.arguments);
  for (let i = 0; i < Math.min(sourceResult.length - 30, 500); i += 15) {
    const chunk = sourceResult.slice(i, i + 30).trim();
    if (chunk.length < 15) continue;
    if (sinkArgs.includes(chunk)) return true;
  }
  return false;
}

// ── Retry storm detection ──

function findRetryStorms(session: SessionInfo): ChainMatch[] {
  const matches: ChainMatch[] = [];
  const calls = session.toolCalls;

  for (let i = 0; i < calls.length - 3; i++) {
    const window = calls.slice(i, i + 4);
    if (window.every((c) => c.toolName === window[0].toolName && c.isError)) {
      matches.push({
        chainName: 'retry-storm',
        sessionId: session.id,
        steps: window.map((c, j) => ({
          index: i + j, toolName: c.toolName,
          summary: `error: ${(c.result || '').slice(0, 50)}`,
        })),
        severity: 'low',
        description: `${window[0].toolName} called ${window.length}+ times with consecutive errors`,
      });
      break;
    }
  }

  return matches;
}

// ── Chain matching engine ──

function findChainMatches(session: SessionInfo): ChainMatch[] {
  const matches: ChainMatch[] = [];
  const calls = session.toolCalls;

  // Retry storms (special handling)
  matches.push(...findRetryStorms(session));

  // Sequence patterns
  for (const pattern of CHAIN_PATTERNS) {
    for (let startIdx = 0; startIdx < calls.length; startIdx++) {
      if (!pattern.steps[0](calls[startIdx])) continue;

      const stepMatches: { index: number; toolName: string; summary: string }[] = [
        { index: startIdx, toolName: calls[startIdx].toolName, summary: extractSummary(calls[startIdx]) },
      ];

      let currentIdx = startIdx;
      let matched = true;

      for (let stepNum = 1; stepNum < pattern.steps.length; stepNum++) {
        let found = false;
        for (let j = currentIdx + 1; j <= Math.min(currentIdx + pattern.maxGap, calls.length - 1); j++) {
          if (pattern.steps[stepNum](calls[j])) {
            stepMatches.push({ index: j, toolName: calls[j].toolName, summary: extractSummary(calls[j]) });
            currentIdx = j;
            found = true;
            break;
          }
        }
        if (!found) { matched = false; break; }
      }

      if (!matched) continue;

      // Content overlap check if required
      if (pattern.requireContentOverlap) {
        if (!hasContentOverlap(calls[stepMatches[0].index], calls[stepMatches[stepMatches.length - 1].index])) {
          continue;
        }
      }

      matches.push({
        chainName: pattern.name,
        sessionId: session.id,
        steps: stepMatches,
        severity: pattern.severity,
        description: pattern.description,
      });
      break; // one match per pattern per session
    }
  }

  return matches;
}

// ── Public API ──

export function analyzeChains(sessions: SessionInfo[]): ChainMatch[] {
  const allMatches: ChainMatch[] = [];
  for (const session of sessions) {
    allMatches.push(...findChainMatches(session));
  }
  return allMatches;
}
