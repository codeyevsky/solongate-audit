import type { ToolCall, SessionInfo, DataFlowLeak } from '../types.js';

// Patterns that identify sensitive data in tool results
const SENSITIVE_PATTERNS: { pattern: RegExp; type: string }[] = [
  { pattern: /sk-[a-zA-Z0-9]{20,}/, type: 'openai_api_key' },
  { pattern: /sk_live_[a-zA-Z0-9]+/, type: 'stripe_key' },
  { pattern: /Bearer\s+[a-zA-Z0-9._\-]{20,}/, type: 'bearer_token' },
  { pattern: /ghp_[a-zA-Z0-9]{36}/, type: 'github_pat' },
  { pattern: /glpat-[a-zA-Z0-9\-]{20,}/, type: 'gitlab_pat' },
  { pattern: /api[_-]?key\s*[:=]\s*['"]?([a-zA-Z0-9_\-]{16,})['"]?/i, type: 'api_key' },
  { pattern: /password\s*[:=]\s*['"]?([^\s'"]{8,})['"]?/i, type: 'password' },
  { pattern: /AWS[_A-Z]*KEY[_A-Z]*\s*[:=]\s*['"]?([A-Z0-9]{16,})['"]?/i, type: 'aws_key' },
  { pattern: /-----BEGIN\s+(RSA\s+)?PRIVATE\s+KEY-----/, type: 'private_key' },
  { pattern: /DATABASE_URL\s*[:=]\s*['"]?([^\s'"]+)['"]?/i, type: 'database_url' },
];

const SENSITIVE_FILE_PATTERNS = [
  /\.env(?:\b|\.production|\.local|\.staging)/,
  /credentials/i,
  /secrets?\b/i,
  /id_rsa/,
  /id_ed25519/,
  /\.pem$/,
  /service.account/i,
  /\.npmrc/,
];

function isSensitiveFileAccess(tc: ToolCall): boolean {
  const argStr = JSON.stringify(tc.arguments).toLowerCase();
  return SENSITIVE_FILE_PATTERNS.some((p) => p.test(argStr));
}

function isNetworkOrExecSink(tc: ToolCall): boolean {
  const t = tc.toolName.toLowerCase();
  const argStr = JSON.stringify(tc.arguments).toLowerCase();
  return t.includes('web') || t.includes('fetch') || t.includes('navigate') ||
    ((t.includes('bash') || t.includes('shell') || t.includes('exec')) &&
     (argStr.includes('curl') || argStr.includes('wget') || argStr.includes('nc ') ||
      argStr.includes('scp ') || argStr.includes('http')));
}

export function analyzeDataFlow(sessions: SessionInfo[]): DataFlowLeak[] {
  const leaks: DataFlowLeak[] = [];

  for (const session of sessions) {
    const calls = session.toolCalls;

    for (let i = 0; i < calls.length; i++) {
      const source = calls[i];
      const sourceResult = source.result || '';
      if (sourceResult.length < 10) continue;

      // Extract sensitive tokens from source result
      const foundTokens: { type: string; value: string }[] = [];
      for (const { pattern, type } of SENSITIVE_PATTERNS) {
        const match = sourceResult.match(pattern);
        if (match) {
          foundTokens.push({ type, value: (match[1] || match[0]).slice(0, 30) });
        }
      }

      const isSensitiveRead = isSensitiveFileAccess(source);
      if (foundTokens.length === 0 && !isSensitiveRead) continue;

      // Scan subsequent tool calls (within 20) for data flow
      for (let j = i + 1; j < Math.min(i + 20, calls.length); j++) {
        const sink = calls[j];
        if (!isNetworkOrExecSink(sink)) continue;

        const sinkArgs = JSON.stringify(sink.arguments);

        // Check token flow
        for (const token of foundTokens) {
          if (sinkArgs.includes(token.value.slice(0, 15))) {
            leaks.push({
              sessionId: session.id,
              sourceIndex: i,
              sinkIndex: j,
              sourceToolName: source.toolName,
              sinkToolName: sink.toolName,
              dataType: token.type,
              pattern: token.value.slice(0, 20) + '...',
            });
            break;
          }
        }

        // Check sensitive file content flow
        if (isSensitiveRead && sourceResult.length > 20) {
          for (let k = 0; k < Math.min(sourceResult.length - 20, 300); k += 20) {
            const chunk = sourceResult.slice(k, k + 20).trim();
            if (chunk.length < 10) continue;
            if (sinkArgs.includes(chunk)) {
              leaks.push({
                sessionId: session.id,
                sourceIndex: i,
                sinkIndex: j,
                sourceToolName: source.toolName,
                sinkToolName: sink.toolName,
                dataType: 'file_content',
                pattern: chunk.slice(0, 20) + '...',
              });
              break;
            }
          }
        }
      }
    }
  }

  return leaks;
}
