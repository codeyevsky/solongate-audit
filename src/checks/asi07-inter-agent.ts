import type { ScanResult, CheckResult, Evidence } from '../types.js';

// OWASP ASI07: Insecure Inter-Agent Communication
// Agent-to-agent messages lack authentication, integrity, or authorization.
// OWASP mitigations: receipt chain tracking, delegation depth monitoring,
// fan-out detection, verified agent identity in every communication.

export function checkInterAgent(scan: ScanResult): CheckResult {
  const code = 'ASI07';
  const title = 'Inter-Agent Comms';
  const evidence: Evidence[] = [];

  // OWASP: Receipt chain tracking — verified identity in every message
  if (scan.hasReceiptChain) {
    evidence.push({ icon: 'found', text: 'Receipt chain tracking — verified agent identity recorded in every communication' });
  } else {
    evidence.push({ icon: 'missing', text: 'No receipt chain — inter-agent messages have no verified identity trail (OWASP: track chain identity)' });
  }

  // OWASP: Delegation depth monitoring — prevent deep delegation chains
  if (scan.maxChainDepth !== null) {
    evidence.push({ icon: 'found', text: `Delegation depth limit: maxChainDepth=${scan.maxChainDepth}` });
  } else {
    evidence.push({ icon: 'missing', text: 'No delegation depth limit — agents can create unlimited delegation chains' });
  }

  // OWASP: Fan-out detection — one agent spawning too many sub-agents
  if (scan.maxFanOut !== null) {
    evidence.push({ icon: 'found', text: `Fan-out limit: maxFanOut=${scan.maxFanOut}` });
  } else {
    evidence.push({ icon: 'missing', text: 'No fan-out limit — one agent can spawn unlimited sub-agents' });
  }

  // Trust map (defines who talks to whom)
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

  // Critical OWASP gaps
  evidence.push({ icon: 'missing', text: 'No agent-to-agent authentication protocol (OWASP: cryptographic verification)' });
  evidence.push({ icon: 'missing', text: 'No encrypted inter-agent communication channel' });
  evidence.push({ icon: 'missing', text: 'No message integrity verification between agents' });

  // PROTECTED: receipt chain + delegation limits + trust map + fan-out
  if (scan.hasReceiptChain && scan.maxChainDepth !== null && scan.hasAgentTrustMap) {
    return {
      code, title, status: 'PROTECTED', evidence,
      summary: 'Inter-agent communication tracked with receipt chains and delegation limits.',
      details: 'Receipt chain records verified identity in every message. Delegation depth limited. Trust map defines communication boundaries. Fan-out detection prevents agent spawning abuse.',
    };
  }

  // PARTIAL: trust map exists with relationships, or delegation limits
  if (scan.hasAgentTrustMap && (scan.trustRelationships > 0 || scan.delegationChains > 0 || scan.maxChainDepth !== null)) {
    return {
      code, title, status: 'PARTIAL', evidence,
      summary: 'Trust boundaries defined but no receipt chain or cryptographic verification.',
      details: 'Agent trust map defines who should talk to whom. But messages are not cryptographically verified. No receipt chain means compromised agents can forge messages without detection.',
      recommendation: 'Add receipt chain tracking. Set maxChainDepth and maxFanOut limits. Add message authentication.',
    };
  }

  return {
    code, title, status: 'NOT_PROTECTED', evidence,
    summary: 'No inter-agent communication security.',
    details: 'Agents communicate without authentication, receipts, or depth limits. A compromised agent can forge messages, impersonate orchestrators, create unlimited delegation chains, and spread malicious instructions.',
    recommendation: 'Define agentTrustMap with trust relationships. Add receipt chain tracking. Set maxChainDepth and maxFanOut limits.',
  };
}
