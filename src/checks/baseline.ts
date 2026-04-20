import type { SessionInfo, SessionBaseline, SessionAnomaly, PermissionDrift, UnsolicitedAction } from '../types.js';

// ── Tool classification ──

function getPrivilegeLevel(toolName: string, args: Record<string, unknown>): number {
  const t = toolName.toLowerCase();
  const argStr = JSON.stringify(args).toLowerCase();

  // Level 4: Network/exfil
  if (t.includes('web') || t.includes('fetch') || t.includes('navigate')) return 4;
  if ((t.includes('bash') || t.includes('shell') || t.includes('exec')) &&
      (argStr.includes('curl') || argStr.includes('wget') || argStr.includes('nc '))) return 4;

  // Level 3: Exec/shell
  if (t.includes('bash') || t.includes('shell') || t.includes('exec') || t.includes('terminal')) return 3;

  // Level 2: Write/edit
  if (t.includes('write') || t.includes('edit') || t.includes('delete') || t.includes('notebook')) return 2;

  // Level 1: Read/search
  return 1;
}

function getToolCategory(toolName: string): string {
  const t = toolName.toLowerCase();
  if (t.includes('read') || t.includes('cat') || t.includes('grep') || t.includes('glob') || t.includes('search')) return 'read';
  if (t.includes('write') || t.includes('edit')) return 'write';
  if (t.includes('bash') || t.includes('shell') || t.includes('exec') || t.includes('terminal')) return 'exec';
  if (t.includes('web') || t.includes('fetch') || t.includes('navigate') || t.includes('browser')) return 'network';
  if (t.includes('task') || t.includes('todo') || t.includes('agent')) return 'orchestration';
  return 'other';
}

// ── Baseline computation ──

function computeBaseline(sessions: SessionInfo[], source: 'claude' | 'gemini' | 'openclaw' | 'all'): SessionBaseline {
  const filtered = source === 'all' ? sessions : sessions.filter((s) => s.source === source);

  const callCounts = filtered.map((s) => s.toolCalls.length);
  const avgToolCalls = callCounts.length > 0 ? callCounts.reduce((a, b) => a + b, 0) / callCounts.length : 0;
  const stddevToolCalls = callCounts.length > 1
    ? Math.sqrt(callCounts.reduce((sum, c) => sum + (c - avgToolCalls) ** 2, 0) / (callCounts.length - 1))
    : 0;

  const durations = filtered
    .filter((s) => s.startTime && s.endTime)
    .map((s) => new Date(s.endTime!).getTime() - new Date(s.startTime).getTime())
    .filter((d) => !isNaN(d) && d > 0);
  const avgDurationMs = durations.length > 0 ? durations.reduce((a, b) => a + b, 0) / durations.length : 0;
  const stddevDurationMs = durations.length > 1
    ? Math.sqrt(durations.reduce((sum, d) => sum + (d - avgDurationMs) ** 2, 0) / (durations.length - 1))
    : 0;

  const totalCalls = filtered.reduce((sum, s) => sum + s.toolCalls.length, 0);
  const categoryCount: Record<string, number> = {};
  for (const s of filtered) {
    for (const tc of s.toolCalls) {
      const cat = getToolCategory(tc.toolName);
      categoryCount[cat] = (categoryCount[cat] || 0) + 1;
    }
  }
  const toolTypeDistribution: Record<string, number> = {};
  for (const [cat, count] of Object.entries(categoryCount)) {
    toolTypeDistribution[cat] = totalCalls > 0 ? (count / totalCalls) * 100 : 0;
  }

  return { source, avgToolCalls, stddevToolCalls, toolTypeDistribution, avgDurationMs, stddevDurationMs };
}

// ── Anomaly detection ──

function detectAnomalies(sessions: SessionInfo[], baselines: SessionBaseline[]): SessionAnomaly[] {
  const anomalies: SessionAnomaly[] = [];
  const allBaseline = baselines.find((b) => b.source === 'all');
  if (!allBaseline || sessions.length < 3) return anomalies;

  for (const session of sessions) {
    const baseline = baselines.find((b) => b.source === session.source) || allBaseline;
    const deviations: string[] = [];

    // Volume anomaly
    if (baseline.stddevToolCalls > 0) {
      const zScore = (session.toolCalls.length - baseline.avgToolCalls) / baseline.stddevToolCalls;
      if (zScore > 2) {
        deviations.push(`tool calls ${zScore.toFixed(1)}x stddev above mean (${session.toolCalls.length} vs avg ${Math.round(baseline.avgToolCalls)})`);
      }
    }

    // Duration anomaly
    if (session.startTime && session.endTime && baseline.stddevDurationMs > 0) {
      const duration = new Date(session.endTime).getTime() - new Date(session.startTime).getTime();
      if (!isNaN(duration) && duration > 0) {
        const zScore = (duration - baseline.avgDurationMs) / baseline.stddevDurationMs;
        if (zScore > 2) {
          deviations.push(`duration ${zScore.toFixed(1)}x stddev above mean`);
        }
      }
    }

    // Tool distribution anomaly
    const sessionCategories: Record<string, number> = {};
    for (const tc of session.toolCalls) {
      const cat = getToolCategory(tc.toolName);
      sessionCategories[cat] = (sessionCategories[cat] || 0) + 1;
    }
    const sessionTotal = session.toolCalls.length || 1;
    for (const [cat, count] of Object.entries(sessionCategories)) {
      const sessionPct = (count / sessionTotal) * 100;
      const baselinePct = baseline.toolTypeDistribution[cat] || 0;
      if (sessionPct > baselinePct * 3 && sessionPct > 10 && baselinePct > 0) {
        deviations.push(`${cat}: ${sessionPct.toFixed(0)}% vs baseline ${baselinePct.toFixed(0)}%`);
      }
    }

    if (deviations.length > 0) {
      anomalies.push({
        sessionId: session.id,
        source: session.source,
        deviations,
        severity: deviations.length >= 3 ? 'high' : deviations.length >= 2 ? 'medium' : 'low',
      });
    }
  }

  return anomalies;
}

// ── Permission drift ──

function detectPermissionDrift(sessions: SessionInfo[]): PermissionDrift[] {
  const drifts: PermissionDrift[] = [];

  for (const session of sessions) {
    const calls = session.toolCalls;
    if (calls.length < 8) continue;

    const mid = Math.floor(calls.length / 2);
    const firstHalf = calls.slice(0, mid);
    const secondHalf = calls.slice(mid);

    const earlyLevels = firstHalf.map((tc) => getPrivilegeLevel(tc.toolName, tc.arguments));
    const lateLevels = secondHalf.map((tc) => getPrivilegeLevel(tc.toolName, tc.arguments));

    const earlyAvg = earlyLevels.reduce((a, b) => a + b, 0) / earlyLevels.length;
    const lateAvg = lateLevels.reduce((a, b) => a + b, 0) / lateLevels.length;
    const driftRatio = earlyAvg > 0 ? lateAvg / earlyAvg : lateAvg;

    const earlyTools = new Set(firstHalf.map((tc) => getToolCategory(tc.toolName)));
    const lateTools = new Set(secondHalf.map((tc) => getToolCategory(tc.toolName)));
    const newToolTypes = [...lateTools].filter((t) => !earlyTools.has(t));

    if (driftRatio > 1.5 || newToolTypes.includes('exec') || newToolTypes.includes('network')) {
      drifts.push({
        sessionId: session.id,
        earlyPrivilegeLevel: earlyAvg,
        latePrivilegeLevel: lateAvg,
        driftRatio,
        newToolTypes,
      });
    }
  }

  return drifts;
}

// ── Unsolicited action detection ──

const CRITICAL_ACTIONS = [
  { pattern: /\b(git\s+push|npm\s+publish|docker\s+push|kubectl\s+apply|terraform\s+apply)\b/i, action: 'deploy' },
  { pattern: /rm\s+-rf\s+[\/~$.*]|del\s+\/[sf]|drop\s+(table|database)/i, action: 'delete' },
  { pattern: /chmod\s+[0-7]{3,4}|chown\b|sudo\b/i, action: 'privilege' },
];

function actionMatchesUserRequest(action: string, userText: string): boolean {
  const lower = userText.toLowerCase();
  switch (action) {
    case 'deploy': return /\b(deploy|push|publish|release|ship|yayınla|gönder)\b/.test(lower);
    case 'delete': return /\b(delete|remove|clean|drop|purge|sil|kaldır|temizle)\b/.test(lower);
    case 'privilege': return /\b(chmod|chown|sudo|permission|root|admin|yetki)\b/.test(lower);
    default: return false;
  }
}

export function findUnsolicitedActions(sessions: SessionInfo[]): UnsolicitedAction[] {
  const unsolicited: UnsolicitedAction[] = [];

  for (const session of sessions) {
    const userMsgs = session.userMessages || [];
    if (userMsgs.length === 0) continue;

    for (let i = 0; i < session.toolCalls.length; i++) {
      const tc = session.toolCalls[i];
      const t = tc.toolName.toLowerCase();
      if (!(t.includes('bash') || t.includes('shell') || t.includes('exec'))) continue;

      const argStr = JSON.stringify(tc.arguments);

      for (const { pattern, action } of CRITICAL_ACTIONS) {
        if (!pattern.test(argStr)) continue;

        const tcTime = new Date(tc.timestamp).getTime();
        const precedingMsgs = userMsgs.filter((um) => new Date(um.timestamp).getTime() < tcTime);
        const lastMsg = precedingMsgs.length > 0 ? precedingMsgs[precedingMsgs.length - 1] : undefined;
        const userRequestedIt = lastMsg && actionMatchesUserRequest(action, lastMsg.text);

        if (!userRequestedIt) {
          unsolicited.push({
            sessionId: session.id,
            toolCallIndex: i,
            toolName: tc.toolName,
            action,
            lastUserMessageBefore: lastMsg?.text.slice(0, 100),
            timeSinceLastUserMessage: lastMsg
              ? tcTime - new Date(lastMsg.timestamp).getTime()
              : undefined,
          });
        }
        break;
      }
    }
  }

  return unsolicited;
}

// ── Public API ──

export function analyzeBaseline(sessions: SessionInfo[]): {
  baselines: SessionBaseline[];
  anomalies: SessionAnomaly[];
  permissionDrifts: PermissionDrift[];
} {
  const sources = [...new Set(sessions.map((s) => s.source))] as ('claude' | 'gemini' | 'openclaw')[];
  const baselines: SessionBaseline[] = [
    computeBaseline(sessions, 'all'),
    ...sources.map((s) => computeBaseline(sessions, s)),
  ];

  const anomalies = detectAnomalies(sessions, baselines);
  const permissionDrifts = detectPermissionDrift(sessions);

  return { baselines, anomalies, permissionDrifts };
}
