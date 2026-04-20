import type { AuditData, CheckResult, DeepAnalysis } from '../types.js';
import { analyzeChains } from './chain-analysis.js';
import { analyzeDataFlow } from './data-flow.js';
import { analyzeBaseline, findUnsolicitedActions } from './baseline.js';
import { checkGoalHijacking } from './asi01-goal-hijacking.js';
import { checkToolMisuse } from './asi02-tool-misuse.js';
import { checkIdentityAbuse } from './asi03-identity-abuse.js';
import { checkSupplyChain } from './asi04-supply-chain.js';
import { checkCodeExecution } from './asi05-code-execution.js';
import { checkMemoryPoisoning } from './asi06-memory-poisoning.js';
import { checkInterAgent } from './asi07-inter-agent.js';
import { checkCascadingFailures } from './asi08-cascading-failures.js';
import { checkHumanTrust } from './asi09-human-trust.js';
import { checkRogueAgents } from './asi10-rogue-agents.js';

export function runAllChecks(data: AuditData): CheckResult[] {
  // Run deep analysis once, share with all checks
  const { baselines, anomalies, permissionDrifts } = analyzeBaseline(data.sessions);
  const deep: DeepAnalysis = {
    chains: analyzeChains(data.sessions),
    dataFlowLeaks: analyzeDataFlow(data.sessions),
    permissionDrifts,
    baselines,
    anomalies,
    unsolicitedActions: findUnsolicitedActions(data.sessions),
  };

  return [
    checkGoalHijacking(data, deep),
    checkToolMisuse(data, deep),
    checkIdentityAbuse(data, deep),
    checkSupplyChain(data),
    checkCodeExecution(data, deep),
    checkMemoryPoisoning(data),
    checkInterAgent(data),
    checkCascadingFailures(data, deep),
    checkHumanTrust(data, deep),
    checkRogueAgents(data, deep),
  ];
}
