import chalk from 'chalk';
import type { CheckResult, CheckStatus, Evidence, AuditData } from './types.js';

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
  const title = '  SolonGate Security Audit \u2014 OWASP Agentic Top 10  ';
  const border = '\u2500'.repeat(title.length);
  console.log(chalk.bold.white('\u250C' + border + '\u2510'));
  console.log(chalk.bold.white('\u2502') + title + chalk.bold.white('\u2502'));
  console.log(chalk.bold.white('\u2514' + border + '\u2518'));
  console.log('');
}

export function printLogSummary(data: AuditData): void {
  if (data.sources.length > 0) {
    console.log(chalk.dim('  AI Tools: ') + data.sources.join(', '));
  } else {
    console.log(chalk.dim('  AI Tools: ') + chalk.red('No AI tool logs found'));
  }

  console.log(chalk.dim('  Sessions: ') + `${data.sessions.length} total, ${data.totalToolCalls} tool calls`);

  if (data.timeRange) {
    const from = new Date(data.timeRange.from).toLocaleDateString();
    const to = new Date(data.timeRange.to).toLocaleDateString();
    console.log(chalk.dim('  Period: ') + `${from} \u2014 ${to}`);
  }

  console.log('');
}

export function calcScore(results: CheckResult[]): { intScore: number; fixCount: number } {
  let score = 0, fixCount = 0;
  for (const r of results) {
    if (r.status === 'PROTECTED') score += 1;
    else if (r.status === 'PARTIAL') score += 0.5;
    if (r.status === 'NOT_PROTECTED') fixCount++;
  }
  return { intScore: Math.floor(score), fixCount };
}

export function printCompactReport(results: CheckResult[]): void {
  const sorted = [...results].sort((a, b) => {
    const order: Record<CheckStatus, number> = { PROTECTED: 0, PARTIAL: 1, NOT_PROTECTED: 2 };
    return order[a.status] - order[b.status];
  });

  for (const r of sorted) {
    console.log(`${STATUS_ICON[r.status]} ${(`${r.code} ${r.title}`).padEnd(24)} ${STATUS_LABEL[r.status]}`);
    console.log(chalk.dim(`   ${r.summary}`));
  }
  console.log('');
}

export function printScore(results: CheckResult[]): void {
  const { intScore, fixCount } = calcScore(results);

  console.log(`  Security Score: ${(intScore >= 7 ? chalk.green : intScore >= 4 ? chalk.yellow : chalk.red).bold(`${intScore}/10`)}`);
  console.log('');

  if (fixCount > 0) {
    console.log(`  Fix ${fixCount} critical issue${fixCount > 1 ? 's' : ''} \u2192 ${chalk.cyan.underline('solongate.com')}`);
  } else if (intScore < 10) {
    console.log(chalk.yellow.dim('  No critical gaps, but improvements possible.'));
  } else {
    console.log(chalk.green.bold('  Maximum protection achieved!'));
  }
  console.log('');
}

export function printDetailedReport(results: CheckResult[]): void {
  const sorted = [...results].sort((a, b) => {
    const order: Record<CheckStatus, number> = { PROTECTED: 0, PARTIAL: 1, NOT_PROTECTED: 2 };
    return order[a.status] - order[b.status];
  });

  console.log(chalk.bold('\u2500'.repeat(56)));
  console.log(chalk.bold('  DETAILED ANALYSIS'));
  console.log(chalk.bold('\u2500'.repeat(56)));
  console.log('');

  for (const r of sorted) {
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

export function printFooter(results: CheckResult[]): void {
  const { intScore, fixCount } = calcScore(results);

  console.log(`  Security Score: ${intScore}/10` + (fixCount > 0 ? ' \u2014 Critical risks detected.' : ''));
  if (fixCount > 0) {
    console.log(`  Run ${chalk.cyan('npx solongate')} to fix \u2192 ${chalk.cyan.underline('solongate.com')}`);
  }
  console.log('');
}
