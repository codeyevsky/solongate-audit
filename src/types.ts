export type CheckStatus = 'PROTECTED' | 'PARTIAL' | 'NOT_PROTECTED';

export interface Evidence {
  icon: 'found' | 'missing' | 'warn' | 'info';
  text: string;
}

export interface CheckResult {
  code: string;
  title: string;
  status: CheckStatus;
  summary: string;
  details: string;
  evidence: Evidence[];
  recommendation?: string;
}

// Normalized tool call from any AI tool
export interface ToolCall {
  id: string;
  toolName: string;
  arguments: Record<string, unknown>;
  result?: string;
  isError?: boolean;
  timestamp: string;
  source: 'claude' | 'gemini' | 'openclaw';
  sessionId: string;
}

export interface SessionInfo {
  id: string;
  source: 'claude' | 'gemini' | 'openclaw';
  startTime: string;
  endTime?: string;
  model?: string;
  toolCalls: ToolCall[];
  filePath: string;
}

export interface AuditData {
  sessions: SessionInfo[];
  totalToolCalls: number;
  sources: string[];  // which AI tools were found
  timeRange: { from: string; to: string } | null;
}
