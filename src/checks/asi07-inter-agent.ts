import type { AuditData, CheckResult, Evidence } from '../types.js';

// OWASP ASI07: Insecure Inter-Agent Communication
// Analyze logs for multi-agent interactions without authentication or trust boundaries.

export function checkInterAgent(data: AuditData): CheckResult {
  const code = 'ASI07';
  const title = 'Inter-Agent Comms';
  const evidence: Evidence[] = [];

  // Check if multiple agents are active
  const agentSources = new Set(data.sessions.map((s) => s.source));
  const multiAgent = agentSources.size > 1;

  // Check for task/delegation tool calls (agent spawning sub-agents)
  let delegationCalls = 0;
  let agentSpawns = 0;

  for (const tc of data.sessions.flatMap((s) => s.toolCalls)) {
    const toolLower = tc.toolName.toLowerCase();
    const argStr = JSON.stringify(tc.arguments).toLowerCase();

    if (toolLower.includes('task') || toolLower.includes('agent') || toolLower.includes('delegate')) {
      delegationCalls++;
    }
    if (argStr.includes('subagent') || argStr.includes('sub_agent') || argStr.includes('spawn')) {
      agentSpawns++;
    }
  }

  evidence.push({ icon: 'info', text: `${agentSources.size} agent source(s): ${[...agentSources].join(', ')}` });

  if (multiAgent) {
    evidence.push({ icon: 'warn', text: 'Multiple agents active — no authenticated communication between them' });
  }

  if (delegationCalls > 0) {
    evidence.push({ icon: 'warn', text: `${delegationCalls} task delegation call(s) — no receipt chain or depth limits` });
  }

  if (agentSpawns > 0) {
    evidence.push({ icon: 'warn', text: `${agentSpawns} sub-agent spawn(s) — no fan-out limit` });
  }

  evidence.push({ icon: 'missing', text: 'No receipt chain — inter-agent messages have no verified identity trail' });
  evidence.push({ icon: 'missing', text: 'No delegation depth limit (maxChainDepth)' });
  evidence.push({ icon: 'missing', text: 'No fan-out limit (maxFanOut)' });
  evidence.push({ icon: 'missing', text: 'No agent-to-agent authentication protocol' });
  evidence.push({ icon: 'missing', text: 'No message integrity verification between agents' });

  if (!multiAgent && delegationCalls === 0) {
    return {
      code, title, status: 'PARTIAL', evidence,
      summary: 'Single-agent usage — no inter-agent security needed yet.',
      details: 'Only one agent source detected. No delegation or sub-agent spawning. Inter-agent security not tested but also not needed for current usage.',
      recommendation: 'When using multi-agent systems, add receipt chain tracking, delegation limits, and authentication.',
    };
  }

  return {
    code, title, status: 'NOT_PROTECTED', evidence,
    summary: multiAgent
      ? 'Multiple agents active with no communication security.'
      : `${delegationCalls} delegation(s) without receipt chain or depth limits.`,
    details: 'Agents communicate without authentication, receipts, or depth limits. A compromised agent can forge messages, create unlimited delegation chains, and spread malicious instructions.',
    recommendation: 'Add receipt chain tracking. Set maxChainDepth and maxFanOut limits. Add agent authentication.',
  };
}
