import { readFileSync, existsSync, readdirSync, statSync } from 'node:fs';
import { resolve, join } from 'node:path';
import { homedir } from 'node:os';
import type { ToolCall, SessionInfo, AuditData } from './types.js';

// ── Claude Code logs ──
// Location: ~/.claude/projects/<project-hash>/<session-id>.jsonl
// Format: JSONL with {"type":"message","message":{"role":"toolResult","toolName":"...","toolCallId":"..."}}
function collectClaude(): SessionInfo[] {
  const sessions: SessionInfo[] = [];
  const claudeDir = resolve(homedir(), '.claude', 'projects');
  if (!existsSync(claudeDir)) return sessions;

  for (const projectDir of readdirSync(claudeDir)) {
    const projectPath = join(claudeDir, projectDir);
    if (!statSync(projectPath).isDirectory()) continue;

    for (const file of readdirSync(projectPath)) {
      if (!file.endsWith('.jsonl')) continue;
      const filePath = join(projectPath, file);
      const sessionId = file.replace('.jsonl', '');

      try {
        const lines = readFileSync(filePath, 'utf-8').split('\n').filter(Boolean);
        const toolCalls: ToolCall[] = [];
        let startTime = '';
        let endTime = '';
        let model = '';

        for (const line of lines) {
          try {
            const entry = JSON.parse(line);
            if (!entry.timestamp) continue;

            if (!startTime) startTime = entry.timestamp;
            endTime = entry.timestamp;

            // Tool use (assistant calling a tool) — Claude uses type: "assistant"
            if (entry.type === 'assistant') {
              const content = entry.message?.content;
              if (Array.isArray(content)) {
                for (const block of content) {
                  if (block.type === 'tool_use') {
                    toolCalls.push({
                      id: block.id || '',
                      toolName: block.name || '',
                      arguments: block.input || {},
                      timestamp: entry.timestamp,
                      source: 'claude',
                      sessionId,
                    });
                  }
                }
              }
              if (entry.message?.model) model = entry.message.model;
            }

            // Tool result — Claude puts tool_result blocks inside type: "user" entries
            if (entry.type === 'user') {
              const content = entry.message?.content;
              if (Array.isArray(content)) {
                for (const block of content) {
                  if (block.type === 'tool_result') {
                    const tc = toolCalls.find((t) => t.id === block.tool_use_id);
                    if (tc) {
                      const resultContent = block.content;
                      if (typeof resultContent === 'string') {
                        tc.result = resultContent.slice(0, 2000);
                      } else if (Array.isArray(resultContent)) {
                        tc.result = resultContent.map((c: any) => c.text || '').join('\n').slice(0, 2000);
                      }
                      tc.isError = !!block.is_error;
                    }
                  }
                }
              }
            }
          } catch {}
        }

        if (toolCalls.length > 0) {
          sessions.push({ id: sessionId, source: 'claude', startTime, endTime, model, toolCalls, filePath });
        }
      } catch {}
    }
  }

  return sessions;
}

// ── Gemini CLI logs ──
// Location: ~/.gemini/tmp/<project>/chats/session-*.json
// Format: Single JSON with messages[].toolCalls[]
function collectGemini(): SessionInfo[] {
  const sessions: SessionInfo[] = [];
  const geminiDir = resolve(homedir(), '.gemini', 'tmp');
  if (!existsSync(geminiDir)) return sessions;

  for (const projectDir of readdirSync(geminiDir)) {
    const chatsDir = join(geminiDir, projectDir, 'chats');
    if (!existsSync(chatsDir) || !statSync(chatsDir).isDirectory()) continue;

    for (const file of readdirSync(chatsDir)) {
      if (!file.startsWith('session-') || !file.endsWith('.json')) continue;
      const filePath = join(chatsDir, file);

      try {
        const data = JSON.parse(readFileSync(filePath, 'utf-8'));
        const toolCalls: ToolCall[] = [];
        const sessionId = data.sessionId || file.replace('.json', '');

        for (const msg of data.messages || []) {
          if (!msg.toolCalls || !Array.isArray(msg.toolCalls)) continue;

          for (const tc of msg.toolCalls) {
            toolCalls.push({
              id: tc.id || '',
              toolName: tc.name || '',
              arguments: tc.arguments || {},
              result: tc.result ? JSON.stringify(tc.result).slice(0, 2000) : undefined,
              timestamp: msg.timestamp || data.startTime || '',
              source: 'gemini',
              sessionId,
            });
          }
        }

        if (toolCalls.length > 0) {
          sessions.push({
            id: sessionId,
            source: 'gemini',
            startTime: data.startTime || '',
            endTime: data.lastUpdated || '',
            model: data.messages?.[0]?.model || '',
            toolCalls,
            filePath,
          });
        }
      } catch {}
    }
  }

  return sessions;
}

// ── OpenClaw logs ──
// Location: ~/.openclaw/agents/main/sessions/<session-id>.jsonl
// Format: JSONL with {"type":"message","message":{"role":"toolResult","toolName":"..."}}
function collectOpenClaw(): SessionInfo[] {
  const sessions: SessionInfo[] = [];
  const oclawDir = resolve(homedir(), '.openclaw', 'agents', 'main', 'sessions');
  if (!existsSync(oclawDir)) return sessions;

  for (const file of readdirSync(oclawDir)) {
    if (!file.endsWith('.jsonl')) continue;
    const filePath = join(oclawDir, file);
    const sessionId = file.replace('.jsonl', '');

    try {
      const lines = readFileSync(filePath, 'utf-8').split('\n').filter(Boolean);
      const toolCalls: ToolCall[] = [];
      let startTime = '';
      let endTime = '';
      let model = '';

      for (const line of lines) {
        try {
          const entry = JSON.parse(line);
          if (!entry.timestamp) continue;

          if (!startTime) startTime = entry.timestamp;
          endTime = entry.timestamp;

          if (entry.type === 'model_change') {
            model = entry.modelId || '';
          }

          // Tool use from assistant — OpenClaw uses type: "toolCall" with "arguments" (not "tool_use"/"input")
          if (entry.type === 'message' && entry.message?.role === 'assistant') {
            const content = entry.message.content;
            if (Array.isArray(content)) {
              for (const block of content) {
                if (block.type === 'toolCall' || block.type === 'tool_use') {
                  toolCalls.push({
                    id: block.id || '',
                    toolName: block.name || '',
                    arguments: block.arguments || block.input || {},
                    timestamp: entry.timestamp,
                    source: 'openclaw',
                    sessionId,
                  });
                }
              }
            }
          }

          // Tool result
          if (entry.type === 'message' && entry.message?.role === 'toolResult') {
            const tc = toolCalls.find((t) => t.id === entry.message.toolCallId);
            if (tc) {
              const content = entry.message.content;
              if (Array.isArray(content)) {
                tc.result = content.map((c: any) => c.text || '').join('\n').slice(0, 2000);
              }
              tc.isError = !!entry.message.isError;
            }
          }
        } catch {}
      }

      if (toolCalls.length > 0) {
        sessions.push({ id: sessionId, source: 'openclaw', startTime, endTime, model, toolCalls, filePath });
      }
    } catch {}
  }

  return sessions;
}

export function collectLogs(): AuditData {
  const claudeSessions = collectClaude();
  const geminiSessions = collectGemini();
  const openclawSessions = collectOpenClaw();

  const sessions = [...claudeSessions, ...geminiSessions, ...openclawSessions]
    .sort((a, b) => (a.startTime || '').localeCompare(b.startTime || ''));

  const sources: string[] = [];
  if (claudeSessions.length > 0) sources.push('Claude Code');
  if (geminiSessions.length > 0) sources.push('Gemini CLI');
  if (openclawSessions.length > 0) sources.push('OpenClaw');

  const allCalls = sessions.flatMap((s) => s.toolCalls);
  const timestamps = allCalls.map((t) => t.timestamp).filter(Boolean).sort();

  return {
    sessions,
    totalToolCalls: allCalls.length,
    sources,
    timeRange: timestamps.length > 0
      ? { from: timestamps[0], to: timestamps[timestamps.length - 1] }
      : null,
  };
}
