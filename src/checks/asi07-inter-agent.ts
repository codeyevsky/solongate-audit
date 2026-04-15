import type { ScanResult, CheckResult, Evidence } from '../types.js';

// OWASP ASI07: Insecure Inter-Agent Communication
// Agents communicate without authentication, encryption, or trust verification.
// PROTECTED = authenticated + encrypted agent-to-agent communication with trust verification
// PARTIAL = trust map exists but no encryption/verification
// NOT_PROTECTED = no inter-agent security at all

export function checkInterAgent(scan: ScanResult): CheckResult {
  const code = 'ASI07';
  const title = 'Inter-Agent Comms';
  const evidence: Evidence[] = [];

  if (scan.hasAgentTrustMap) {
    if (scan.trustRelationships > 0) {
      evidence.push({ icon: 'found', text: `${scan.trustRelationships} trust relationship(s) defined between agents` });
    }
    if (scan.delegationChains > 0) {
      evidence.push({ icon: 'found', text: `${scan.delegationChains} delegation chain(s) with forwarding rules` });
    }
    if (scan.agentGroups.length > 0) {
      evidence.push({ icon: 'found', text: `Agent groups: ${scan.agentGroups.join(', ')}` });
    }
  } else {
    evidence.push({ icon: 'missing', text: 'No agent trust map — no trust boundaries between agents' });
  }

  // Critical gaps
  evidence.push({ icon: 'missing', text: 'No agent-to-agent authentication protocol' });
  evidence.push({ icon: 'missing', text: 'No encrypted inter-agent communication channel' });
  evidence.push({ icon: 'missing', text: 'No message integrity verification between agents' });

  // Even with a trust map, inter-agent communication security is not solved
  // Trust map defines who SHOULD talk to whom, but doesn't enforce communication security
  if (scan.hasAgentTrustMap && scan.trustRelationships > 0 && scan.delegationChains > 0) {
    return {
      code, title, status: 'PARTIAL', evidence,
      summary: 'Trust boundaries defined but communication is not authenticated or encrypted.',
      details: 'Agent trust map defines trust relationships and delegation rules. But inter-agent messages are not cryptographically authenticated or encrypted. A compromised agent can forge messages.',
      recommendation: 'Implement authenticated inter-agent communication protocol with message signing.',
    };
  }

  return {
    code, title, status: 'NOT_PROTECTED', evidence,
    summary: 'No inter-agent communication security.',
    details: 'Agents can communicate without authentication, encryption, or trust verification. A compromised agent can send forged messages to other agents, escalate privileges, or spread malicious instructions across the system.',
    recommendation: 'Define agentTrustMap in policy. Implement authenticated agent communication protocol.',
  };
}
