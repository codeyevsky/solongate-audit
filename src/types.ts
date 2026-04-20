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

export interface UserMessage {
  timestamp: string;
  text: string;
  nextToolCallIndex?: number;
}

export interface SessionInfo {
  id: string;
  source: 'claude' | 'gemini' | 'openclaw';
  startTime: string;
  endTime?: string;
  model?: string;
  toolCalls: ToolCall[];
  userMessages?: UserMessage[];
  filePath: string;
}

export interface AuditData {
  sessions: SessionInfo[];
  totalToolCalls: number;
  sources: string[];  // which AI tools were found
  timeRange: { from: string; to: string } | null;
}

// ── Deep Analysis Types ──

export interface ChainMatch {
  chainName: string;
  sessionId: string;
  steps: { index: number; toolName: string; summary: string }[];
  severity: 'high' | 'medium' | 'low';
  description: string;
}

export interface DataFlowLeak {
  sessionId: string;
  sourceIndex: number;
  sinkIndex: number;
  sourceToolName: string;
  sinkToolName: string;
  dataType: string;
  pattern: string;
}

export interface PermissionDrift {
  sessionId: string;
  earlyPrivilegeLevel: number;
  latePrivilegeLevel: number;
  driftRatio: number;
  newToolTypes: string[];
}

export interface SessionBaseline {
  source: 'claude' | 'gemini' | 'openclaw' | 'all';
  avgToolCalls: number;
  stddevToolCalls: number;
  toolTypeDistribution: Record<string, number>;
  avgDurationMs: number;
  stddevDurationMs: number;
}

export interface SessionAnomaly {
  sessionId: string;
  source: string;
  deviations: string[];
  severity: 'high' | 'medium' | 'low';
}

export interface UnsolicitedAction {
  sessionId: string;
  toolCallIndex: number;
  toolName: string;
  action: string;
  lastUserMessageBefore?: string;
  timeSinceLastUserMessage?: number;
}

export interface DeepAnalysis {
  chains: ChainMatch[];
  dataFlowLeaks: DataFlowLeak[];
  permissionDrifts: PermissionDrift[];
  baselines: SessionBaseline[];
  anomalies: SessionAnomaly[];
  unsolicitedActions: UnsolicitedAction[];
}
