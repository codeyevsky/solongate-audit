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

export interface ConfigFile<T = unknown> {
  path: string;
  content: T;
}

export interface McpServerConfig {
  command: string;
  args?: string[];
  env?: Record<string, string>;
}

export interface McpConfigFile {
  mcpServers: Record<string, McpServerConfig>;
}

export interface PolicyRule {
  id?: string;
  description?: string;
  effect: 'ALLOW' | 'DENY';
  toolPattern: string;
  priority?: number;
  minimumTrustLevel?: string;
  commandConstraints?: { allowed?: string[]; denied?: string[] };
  pathConstraints?: { allowed?: string[]; denied?: string[]; rootDirectory?: string };
  filenameConstraints?: { allowed?: string[]; denied?: string[] };
  urlConstraints?: { allowed?: string[]; denied?: string[] };
  enabled?: boolean;
}

export interface AgentTrustMapConfig {
  groups?: Record<string, { members: string[]; rules: unknown[] }>;
  relationships?: Array<{ source: string; target: string; type: string; trustLevel?: string }>;
  delegations?: Array<{ chain: string[]; effectiveTools?: string[] }>;
}

export interface PolicySet {
  name?: string;
  rules: PolicyRule[];
  agentTrustMap?: AgentTrustMapConfig;
}

export interface PackageJson {
  name?: string;
  dependencies?: Record<string, string>;
  devDependencies?: Record<string, string>;
  scripts?: Record<string, string>;
}

export interface HookEntry {
  matcher?: string;
  hooks?: Array<{ type: string; command: string }>;
}

export interface HookConfig {
  hooks?: {
    PreToolUse?: HookEntry[];
    PostToolUse?: HookEntry[];
    Stop?: HookEntry[];
  };
}

export interface ServerInfo {
  name: string;
  source: string;
  proxy: string | null;
  isDangerous: boolean;
  detectedTools: string[];
  usesLatestTag: boolean;
}

export interface ScanResult {
  projectRoot: string;
  aiTools: string[];

  // Configs
  mcpConfig: ConfigFile<McpConfigFile> | null;
  claudeDesktopConfig: ConfigFile<McpConfigFile> | null;
  cursorConfig: ConfigFile<McpConfigFile> | null;
  geminiConfig: ConfigFile<McpConfigFile> | null;
  openclawConfig: ConfigFile<McpConfigFile> | null;
  policyConfig: ConfigFile<PolicySet> | null;
  packageJson: ConfigFile<PackageJson> | null;
  claudeSettings: ConfigFile<HookConfig> | null;
  geminiSettings: ConfigFile<HookConfig> | null;

  // Server analysis
  servers: ServerInfo[];
  proxiedCount: number;
  unprotectedCount: number;
  dangerousUnprotected: string[];
  allProxyArgs: string[];

  // Policy analysis
  denyRules: PolicyRule[];
  allowRules: PolicyRule[];
  hasCommandRestrictions: boolean;
  hasFileRestrictions: boolean;
  hasUrlRestrictions: boolean;
  hasPathRestrictions: boolean;
  hasDenyAllRule: boolean;
  hasAgentTrustMap: boolean;
  agentGroups: string[];
  trustRelationships: number;
  delegationChains: number;

  // Hook analysis
  hasPreToolHook: boolean;
  hasPostToolHook: boolean;
  hasStopHook: boolean;
  hasGuardHook: boolean;
  hasAuditHook: boolean;

  // Filesystem
  hasDockerfile: boolean;
  hasGitignore: boolean;
  gitignoreHasEnv: boolean;
  hasEnvFile: boolean;
  hasLockFile: boolean;
  hasWildcardVersions: boolean;
  hasDependabot: boolean;
  hasPreCommitHooks: boolean;

  // Dependencies
  loggingDeps: string[];
  errorTrackingDeps: string[];
  rateLimitDeps: string[];

  // Proxy flags
  hasRateLimitFlag: boolean;
  hasAiJudgeFlag: boolean;
  hasNoInputGuardFlag: boolean;
}
