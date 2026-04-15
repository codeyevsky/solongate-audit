import { readFileSync, existsSync } from 'node:fs';
import { resolve, join } from 'node:path';
import { homedir, platform } from 'node:os';
import type { ScanResult, ConfigFile, McpConfigFile, PolicySet, PackageJson, HookConfig, McpServerConfig, ServerInfo } from './types.js';

function tryJson<T>(root: string, paths: string[]): ConfigFile<T> | null {
  for (const rel of paths) {
    const full = resolve(root, rel);
    if (existsSync(full)) {
      try { return { path: full, content: JSON.parse(readFileSync(full, 'utf-8')) as T }; } catch {}
    }
  }
  return null;
}

function claudeDesktopPath(): string[] {
  const h = homedir(), os = platform();
  if (os === 'darwin') return [join(h, 'Library', 'Application Support', 'Claude', 'claude_desktop_config.json')];
  if (os === 'win32') return [join(h, 'AppData', 'Roaming', 'Claude', 'claude_desktop_config.json')];
  return [join(h, '.config', 'Claude', 'claude_desktop_config.json')];
}

const PROXIES = ['@solongate/proxy', 'solongate-proxy', 'mcp-proxy', 'mcp-guard', 'mcp-firewall'];

function detectProxy(srv: McpServerConfig): string | null {
  const full = [srv.command, ...(srv.args ?? [])].join(' ').toLowerCase();
  for (const p of PROXIES) if (full.includes(p)) return p;
  if (srv.command.toLowerCase().includes('proxy')) return srv.command;
  return null;
}

function detectTools(srv: McpServerConfig): string[] {
  const full = [srv.command, ...(srv.args ?? [])].join(' ').toLowerCase();
  const tools: string[] = [];
  if (full.includes('filesystem') || full.includes('server-filesystem')) tools.push('file_read', 'file_write');
  if (full.includes('playwright') || full.includes('puppeteer') || full.includes('browser')) tools.push('browser_navigate', 'browser_evaluate');
  if (full.includes('shell') || full.includes('terminal') || full.includes('exec')) tools.push('shell_exec');
  if (full.includes('postgres') || full.includes('mysql') || full.includes('sqlite') || full.includes('database')) tools.push('db_query');
  if (full.includes('github') || full.includes('gitlab')) tools.push('git_ops');
  if (full.includes('docker') || full.includes('kubernetes')) tools.push('container_exec');
  if (full.includes('aws') || full.includes('gcp') || full.includes('azure')) tools.push('cloud_ops');
  return tools;
}

const DANGEROUS = ['file_write', 'shell_exec', 'db_query', 'container_exec', 'cloud_ops', 'browser_evaluate'];

function hasDep(pkg: PackageJson | null, deps: string[]): string[] {
  if (!pkg) return [];
  const all = { ...pkg.dependencies, ...pkg.devDependencies };
  return deps.filter((d) => d in all);
}

export function scanProject(root: string): ScanResult {
  // ── Load configs ──
  const mcpConfig = tryJson<McpConfigFile>(root, ['.mcp.json', 'mcp.json', '.claude/mcp.json']);
  const cursorConfig = tryJson<McpConfigFile>(root, ['.cursor/mcp.json']);
  const geminiConfig = tryJson<McpConfigFile>(root, ['.gemini/mcp.json']);
  const openclawConfig = tryJson<McpConfigFile>(root, ['.openclaw/mcp.json', '.openclaw/config.json']);
  const claudeSettings = tryJson<HookConfig>(root, ['.claude/settings.json']);
  const geminiSettings = tryJson<HookConfig>(root, ['.gemini/settings.json']);
  const policyConfig = tryJson<PolicySet>(root, ['policy.json', 'solongate.json', 'solongate.config.json', 'mcp-policy.json', 'agent-policy.json']);
  const packageJson = tryJson<PackageJson>(root, ['package.json']);

  let claudeDesktopConfig: ConfigFile<McpConfigFile> | null = null;
  for (const p of claudeDesktopPath()) {
    if (existsSync(p)) { try { claudeDesktopConfig = { path: p, content: JSON.parse(readFileSync(p, 'utf-8')) }; } catch {} break; }
  }

  // ── Analyze servers ──
  const servers: ServerInfo[] = [];
  const allProxyArgs: string[] = [];
  const allConfigs = [mcpConfig, claudeDesktopConfig, cursorConfig, geminiConfig, openclawConfig].filter(Boolean);

  for (const cfg of allConfigs) {
    if (!cfg) continue;
    for (const [name, srv] of Object.entries(cfg.content.mcpServers ?? {})) {
      const proxy = detectProxy(srv);
      const tools = detectTools(srv);
      const isDangerous = tools.some((t) => DANGEROUS.includes(t));
      const usesLatest = (srv.args ?? []).some((a) => a.includes('@latest'));

      if (proxy) allProxyArgs.push(...(srv.args ?? []));

      servers.push({ name, source: cfg.path, proxy, isDangerous, detectedTools: tools, usesLatest });
    }
  }

  const proxied = servers.filter((s) => s.proxy);
  const unprotected = servers.filter((s) => !s.proxy);
  const dangerousUnprotected = unprotected.filter((s) => s.isDangerous).map((s) => s.name);

  // ── Analyze policy ──
  const rules = (policyConfig?.content.rules ?? []).filter((r) => r.enabled !== false);
  const denyRules = rules.filter((r) => r.effect === 'DENY');
  const allowRules = rules.filter((r) => r.effect === 'ALLOW');
  const tm = policyConfig?.content.agentTrustMap;

  // ── Analyze hooks ──
  const ch = claudeSettings?.content.hooks;
  const gh = geminiSettings?.content.hooks;

  // ── Gitignore ──
  let gitignoreText: string | null = null;
  const gp = resolve(root, '.gitignore');
  if (existsSync(gp)) { try { gitignoreText = readFileSync(gp, 'utf-8'); } catch {} }

  // ── AI tools detected ──
  const aiTools: string[] = [];
  if (mcpConfig || claudeDesktopConfig || claudeSettings) aiTools.push('Claude Code');
  if (geminiConfig || geminiSettings) aiTools.push('Gemini CLI');
  if (openclawConfig) aiTools.push('OpenClaw');
  if (cursorConfig) aiTools.push('Cursor');

  // ── Deps ──
  const pkg = packageJson?.content ?? null;
  const allDeps = { ...pkg?.dependencies, ...pkg?.devDependencies };

  return {
    projectRoot: root,
    aiTools,
    mcpConfig, claudeDesktopConfig, cursorConfig, geminiConfig, openclawConfig,
    policyConfig, packageJson, claudeSettings, geminiSettings,

    servers,
    proxiedCount: proxied.length,
    unprotectedCount: unprotected.length,
    dangerousUnprotected,
    allProxyArgs,

    denyRules, allowRules,
    hasCommandRestrictions: denyRules.some((r) => r.commandConstraints?.denied?.length),
    hasFileRestrictions: denyRules.some((r) => r.filenameConstraints?.denied?.length),
    hasUrlRestrictions: denyRules.some((r) => r.urlConstraints?.denied?.length),
    hasPathRestrictions: denyRules.some((r) => r.pathConstraints?.denied?.length || r.pathConstraints?.rootDirectory),
    hasDenyAllRule: denyRules.some((r) => r.toolPattern === '*' && (r.priority ?? 999) <= 1 && !r.commandConstraints && !r.filenameConstraints && !r.urlConstraints),
    hasAgentTrustMap: !!tm,
    agentGroups: tm?.groups ? Object.keys(tm.groups) : [],
    trustRelationships: tm?.relationships?.length ?? 0,
    delegationChains: tm?.delegations?.length ?? 0,

    hasPreToolHook: !!(ch?.PreToolUse?.length || gh?.PreToolUse?.length),
    hasPostToolHook: !!(ch?.PostToolUse?.length || gh?.PostToolUse?.length),
    hasStopHook: !!(ch?.Stop?.length) || existsSync(resolve(root, '.solongate', 'hooks', 'stop.mjs')),
    hasGuardHook: existsSync(resolve(root, '.solongate', 'hooks', 'guard.mjs')),
    hasAuditHook: existsSync(resolve(root, '.solongate', 'hooks', 'audit.mjs')),

    hasDockerfile: existsSync(resolve(root, 'Dockerfile')),
    hasGitignore: !!gitignoreText,
    gitignoreHasEnv: !!gitignoreText && /\.env/i.test(gitignoreText),
    hasEnvFile: existsSync(resolve(root, '.env')),
    hasLockFile: ['package-lock.json', 'pnpm-lock.yaml', 'yarn.lock', 'bun.lockb'].some((f) => existsSync(resolve(root, f))),
    hasWildcardVersions: Object.values(allDeps).some((v) => v === '*' || v === 'latest'),
    hasDependabot: existsSync(resolve(root, '.github', 'dependabot.yml')) || existsSync(resolve(root, '.github', 'dependabot.yaml')),
    hasPreCommitHooks: existsSync(resolve(root, '.husky')) || existsSync(resolve(root, '.pre-commit-config.yaml')),

    loggingDeps: hasDep(pkg, ['winston', 'pino', 'bunyan', 'morgan', 'log4js']),
    errorTrackingDeps: hasDep(pkg, ['@sentry/node', '@sentry/nextjs', '@bugsnag/node', 'dd-trace', 'newrelic']),
    rateLimitDeps: hasDep(pkg, ['express-rate-limit', 'rate-limiter-flexible', '@fastify/rate-limit', 'bottleneck']),

    hasRateLimitFlag: allProxyArgs.some((a) => a.includes('rate-limit')),
    hasAiJudgeFlag: allProxyArgs.some((a) => a === '--ai-judge'),
    hasNoInputGuardFlag: allProxyArgs.some((a) => a === '--no-input-guard'),
  };
}
