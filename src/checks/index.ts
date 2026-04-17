import type { AuditData, CheckResult } from '../types.js';
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

const ALL_CHECKS = [
  checkGoalHijacking,
  checkToolMisuse,
  checkIdentityAbuse,
  checkSupplyChain,
  checkCodeExecution,
  checkMemoryPoisoning,
  checkInterAgent,
  checkCascadingFailures,
  checkHumanTrust,
  checkRogueAgents,
];

export function runAllChecks(data: AuditData): CheckResult[] {
  return ALL_CHECKS.map((check) => check(data));
}
