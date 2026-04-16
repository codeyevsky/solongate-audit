import chalk from 'chalk';
import type { CheckResult, CheckStatus, Evidence, ScanResult } from './types.js';

const STATUS_ICON: Record<CheckStatus, string> = {
  PROTECTED: chalk.green('\u2705'),
  PARTIAL: chalk.yellow('\u26A0\uFE0F'),
  NOT_PROTECTED: chalk.red('\u274C'),
};

const STATUS_LABEL: Record<CheckStatus, string> = {
  PROTECTED: chalk.green.bold('PROTECTED'),
  PARTIAL: chalk.yellow.bold('PARTIAL'),
  NOT_PROTECTED: chalk.red.bold('NOT PROTECTED'),
};

const EV_ICON: Record<Evidence['icon'], string> = {
  found: chalk.green('\u2022'),
  missing: chalk.red('\u2022'),
  warn: chalk.yellow('\u2022'),
  info: chalk.dim('\u2022'),
};

export function printHeader(): void {
  console.log('');
  const title = '  AI Agent Security Audit \u2014 OWASP Agentic Top 10  ';
  const border = '\u2500'.repeat(title.length);
  console.log(chalk.bold.white('\u250C' + border + '\u2510'));
  console.log(chalk.bold.white('\u2502') + title + chalk.bold.white('\u2502'));
  console.log(chalk.bold.white('\u2514' + border + '\u2518'));
  console.log('');
}

export function printScanSummary(scan: ScanResult): void {
  console.log(chalk.dim('  Scanned: ') + scan.projectRoot);

  if (scan.aiTools.length > 0) {
    console.log(chalk.dim('  AI Tools: ') + scan.aiTools.join(', '));
  }

  const found: string[] = [];
  if (scan.mcpConfig) found.push('.mcp.json');
  if (scan.policyConfig) found.push(scan.policyConfig.path.split(/[/\\]/).pop()!);
  if (scan.claudeSettings) found.push('.claude/settings.json');
  if (scan.geminiSettings) found.push('.gemini/settings.json');
  if (scan.cursorConfig) found.push('.cursor/mcp.json');
  if (scan.openclawConfig) found.push('.openclaw/');
  if (scan.hasGuardHook || scan.hasAuditHook) found.push('hooks/');
  if (scan.hasDockerfile) found.push('Dockerfile');
  if (scan.hasLockFile) found.push('lock file');
  if (scan.hasDependabot) found.push('dependabot');

  if (found.length > 0) {
    console.log(chalk.dim('  Configs: ') + found.join(', '));
  } else {
    console.log(chalk.dim('  Configs: ') + chalk.red('No security configurations detected'));
  }

  console.log(chalk.dim('  Servers: ') +
    (scan.servers.length > 0
      ? `${scan.servers.length} total` +
        (scan.proxiedCount > 0 ? chalk.green(`, ${scan.proxiedCount} proxied`) : '') +
        (scan.unprotectedCount > 0 ? chalk.red(`, ${scan.unprotectedCount} unprotected`) : '') +
        (scan.dangerousUnprotected.length > 0 ? chalk.red.bold(` (${scan.dangerousUnprotected.length} dangerous!)`) : '')
      : chalk.dim('none')));
  console.log('');
}

export function printCompactReport(results: CheckResult[]): void {
  const sorted = [...results].sort((a, b) => {
    const order: Record<CheckStatus, number> = { PROTECTED: 0, PARTIAL: 1, NOT_PROTECTED: 2 };
    return order[a.status] - order[b.status];
  });

  for (const r of sorted) {
    console.log(`${STATUS_ICON[r.status]} ${(`${r.code} ${r.title}`).padEnd(24)} ${STATUS_LABEL[r.status]}`);
  }
  console.log('');
}

export function printScore(results: CheckResult[]): void {
  let score = 0, fixCount = 0;
  for (const r of results) {
    if (r.status === 'PROTECTED') score += 1;
    else if (r.status === 'PARTIAL') score += 0.5;
    if (r.status === 'NOT_PROTECTED') fixCount++;
  }
  const intScore = Math.floor(score);

  const barLen = 30;
  const filled = Math.round((intScore / 10) * barLen);
  const color = intScore >= 7 ? chalk.green : intScore >= 4 ? chalk.yellow : chalk.red;
  console.log(`  ${color('\u2588'.repeat(filled))}${chalk.dim('\u2591'.repeat(barLen - filled))}  ${color.bold(`${intScore}/10`)}`);
  console.log('');

  if (fixCount > 0) {
    console.log(chalk.dim(`  ${fixCount} critical gap${fixCount > 1 ? 's' : ''} detected`) + chalk.dim(' — run with --detailed for recommendations'));
  } else if (intScore < 10) {
    console.log(chalk.yellow.dim('  No critical gaps, but improvements possible.'));
  } else {
    console.log(chalk.green.bold('  Maximum protection achieved!'));
  }
  console.log('');
}

export function printDetailedReport(results: CheckResult[]): void {
  console.log(chalk.bold('\u2500'.repeat(56)));
  console.log(chalk.bold('  DETAILED ANALYSIS'));
  console.log(chalk.bold('\u2500'.repeat(56)));
  console.log('');

  for (const r of results) {
    console.log(`  ${STATUS_ICON[r.status]} ${chalk.bold(`${r.code} ${r.title}`)}  ${STATUS_LABEL[r.status]}`);
    console.log(`     ${r.summary}`);
    console.log('');

    for (const e of r.evidence) {
      const lines = e.text.split('\n');
      console.log(`     ${EV_ICON[e.icon]} ${lines[0]}`);
      for (let i = 1; i < lines.length; i++) console.log(`       ${lines[i]}`);
    }
    console.log('');

    console.log(`     ${chalk.dim(r.details)}`);

    if (r.recommendation) {
      console.log('');
      console.log(`     ${chalk.cyan('\u279C')} ${chalk.cyan(r.recommendation)}`);
    }

    console.log('');
    console.log(chalk.dim('     ' + '\u2500'.repeat(46)));
    console.log('');
  }
}
