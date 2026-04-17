import type { AuditData, CheckResult, Evidence } from '../types.js';

// OWASP ASI09: Human-Agent Trust Exploitation
// Analyze logs for actions taken without human approval — critical operations with no review gate.

// Deploy/publish tools are critical — bash/shell are tracked but not critical by themselves
const HIGH_IMPACT_TOOLS = ['deploy', 'publish'];
const SHELL_TOOLS = ['bash', 'shell', 'exec', 'terminal'];

export function checkHumanTrust(data: AuditData): CheckResult {
  const code = 'ASI09';
  const title = 'Human-Agent Trust';
  const evidence: Evidence[] = [];

  let shellCalls = 0;
  let writeOps = 0;
  let deleteOps = 0;
  let deployOps = 0;

  for (const tc of data.sessions.flatMap((s) => s.toolCalls)) {
    const toolLower = tc.toolName.toLowerCase();
    const argStr = JSON.stringify(tc.arguments).toLowerCase();

    if (SHELL_TOOLS.some((ct) => toolLower.includes(ct)) || HIGH_IMPACT_TOOLS.some((ct) => toolLower.includes(ct))) {
      shellCalls++;
    }

    if (toolLower.includes('write') || toolLower.includes('edit') || toolLower.includes('notebookedit')) {
      writeOps++;
    }

    // Only check deploy/delete in shell tools — not file writes mentioning these words
    const isShellTool = SHELL_TOOLS.some((ct) => toolLower.includes(ct));
    if (isShellTool) {
      // Only count truly destructive deletions, not normal dev cleanup
      if (/rm\s+-rf\s+[\/~$.*]/.test(argStr) || /del\s+\/[sf]/i.test(argStr) || /drop\s+(table|database)/i.test(argStr)) {
        deleteOps++;
      }

      // Only count actual deploy/publish COMMANDS
      if (/\b(git\s+push|npm\s+publish|docker\s+push|kubectl\s+apply|terraform\s+apply)\b/.test(argStr)) {
        deployOps++;
      }
    }
  }

  evidence.push({ icon: 'info', text: `${shellCalls} shell/exec call(s) in ${data.sessions.length} session(s)` });
  evidence.push({ icon: 'info', text: `${writeOps} file write(s), ${deleteOps} delete operation(s), ${deployOps} deploy/publish action(s)` });

  if (deployOps > 0) {
    evidence.push({ icon: 'warn', text: `${deployOps} deploy/publish action(s) executed without human approval gate` });
  }
  if (deleteOps > 0) {
    evidence.push({ icon: 'warn', text: `${deleteOps} delete operation(s) executed without human approval gate` });
  }

  evidence.push({ icon: 'missing', text: 'No approval routing — critical actions not routed for human review' });
  evidence.push({ icon: 'missing', text: 'No raw intent routing — humans may see agent-reframed summaries' });
  evidence.push({ icon: 'missing', text: 'No policy-generated explanations — agents frame their own requests' });
  evidence.push({ icon: 'missing', text: 'No protection against approval fatigue' });

  if (shellCalls === 0) {
    return {
      code, title, status: 'PARTIAL', evidence,
      summary: 'No critical actions in logs, but no approval workflow exists.',
      details: 'No file writes, deletions, or deployments detected. But no human approval workflow exists — when critical actions occur, they will execute without review.',
      recommendation: 'Implement approval routing for critical actions. Add raw intent display.',
    };
  }

  if (deployOps === 0 && deleteOps === 0) {
    return {
      code, title, status: 'PARTIAL', evidence,
      summary: `${shellCalls} shell calls without approval routing, but no high-impact actions.`,
      details: 'Shell commands executed without human approval workflow. No deployments or destructive deletions detected. But no approval routing exists for when high-impact actions occur.',
      recommendation: 'Implement approval routing. Add raw intent routing. Ensure policy-generated explanations.',
    };
  }

  return {
    code, title, status: 'NOT_PROTECTED', evidence,
    summary: `${deployOps + deleteOps} high-impact action(s) executed without human approval.`,
    details: 'Deployments, deletions, or publishes executed without human review. No approval routing, no raw intent display, no policy-generated explanations. Agents can manipulate framing to gain trust.',
    recommendation: 'Implement approval routing for critical actions. Add raw intent display. Ensure policy-generated explanations.',
  };
}
