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

// ── Log viewer ──

const SOURCE_COLOR: Record<string, (s: string) => string> = {
  claude: chalk.magenta,
  gemini: chalk.blue,
  openclaw: chalk.green,
};

const SOURCE_LABEL: Record<string, string> = {
  claude: 'Claude',
  gemini: 'Gemini',
  openclaw: 'OClaw',
};

function truncate(s: string, max: number): string {
  if (s.length <= max) return s;
  return s.slice(0, max - 1) + '\u2026';
}

function formatTime(ts: string): string {
  if (!ts) return '          ';
  try {
    const d = new Date(ts);
    return d.toLocaleTimeString('en-GB', { hour: '2-digit', minute: '2-digit', second: '2-digit' });
  } catch {
    return ts.slice(11, 19);
  }
}

function formatDate(ts: string): string {
  if (!ts) return '';
  try {
    const d = new Date(ts);
    return d.toLocaleDateString('en-GB', { day: '2-digit', month: '2-digit' });
  } catch {
    return '';
  }
}

function extractArgSummary(args: Record<string, unknown>): string {
  if (args.command) return String(args.command);
  if (args.file_path) return String(args.file_path);
  if (args.path) return String(args.path);
  if (args.pattern) return String(args.pattern);
  if (args.url) return String(args.url);
  if (args.query) return String(args.query);
  if (args.old_string) return `"${String(args.old_string).slice(0, 30)}" \u2192 "${String(args.new_string || '').slice(0, 30)}"`;
  if (args.content) return `[${String(args.content).length} chars]`;
  const keys = Object.keys(args);
  if (keys.length > 0) return JSON.stringify(args);
  return '';
}

export function printToolCall(tc: { id: string; toolName: string; arguments: Record<string, unknown>; result?: string; isError?: boolean; timestamp: string; source: string; sessionId: string }, detailed: boolean = false, model?: string): void {
  const color = SOURCE_COLOR[tc.source] || chalk.white;
  const label = SOURCE_LABEL[tc.source] || tc.source;
  const time = formatTime(tc.timestamp);
  const tool = truncate(tc.toolName, 16);
  const errorMark = tc.isError ? chalk.red(' ERR') : '';

  if (!detailed) {
    // Compact mode — single line
    const argSummary = truncate(extractArgSummary(tc.arguments).replace(/[\n\r]/g, ' '), 70);
    console.log(
      `  ${chalk.dim(time)} ${color(label.padEnd(6))} ${chalk.white(tool.padEnd(17))} ${chalk.dim(argSummary)}${errorMark}`
    );
    return;
  }

  // Detailed mode — multi-line with all fields
  console.log(
    `  ${chalk.dim(time)} ${color(label.padEnd(6))} ${chalk.white.bold(tool)}${errorMark}`
  );
  console.log(`  ${' '.repeat(9)}${chalk.dim('ID:')} ${chalk.dim(tc.id.slice(0, 12))}  ${chalk.dim('Session:')} ${chalk.dim(tc.sessionId.slice(0, 12))}${model ? '  ' + chalk.dim('Model:') + ' ' + chalk.dim(model) : ''}`);

  // Full arguments
  const argStr = extractArgSummary(tc.arguments).replace(/[\n\r]/g, ' ');
  if (argStr.length > 0) {
    if (argStr.length <= 120) {
      console.log(`  ${' '.repeat(9)}${chalk.cyan('\u25B8')} ${argStr}`);
    } else {
      // Multi-line for long args
      const lines = argStr.match(/.{1,120}/g) || [argStr];
      console.log(`  ${' '.repeat(9)}${chalk.cyan('\u25B8')} ${lines[0]}`);
      for (let i = 1; i < Math.min(lines.length, 4); i++) {
        console.log(`  ${' '.repeat(11)}${lines[i]}`);
      }
      if (lines.length > 4) console.log(`  ${' '.repeat(11)}${chalk.dim(`... +${lines.length - 4} more lines`)}`);
    }
  }

  // Result preview
  if (tc.result) {
    const resultStr = tc.result.replace(/[\n\r]+/g, ' ').trim();
    if (resultStr.length > 0) {
      const icon = tc.isError ? chalk.red('\u2718') : chalk.green('\u2714');
      const preview = truncate(resultStr, 120);
      console.log(`  ${' '.repeat(9)}${icon} ${chalk.dim(preview)}`);
    }
  }
  console.log('');
}

export function printLogs(data: AuditData, limit: number = 50, detailed: boolean = true): void {
  console.log('');
  console.log(chalk.bold('  Recent Tool Calls'));
  console.log(chalk.dim('  ' + '\u2500'.repeat(90)));
  if (!detailed) {
    console.log(chalk.dim('  Time     Source Tool              Arguments'));
    console.log(chalk.dim('  ' + '\u2500'.repeat(90)));
  }

  const sessionMap = new Map(data.sessions.map((s) => [s.id, s]));

  const allCalls = data.sessions
    .flatMap((s) => s.toolCalls)
    .sort((a, b) => (a.timestamp || '').localeCompare(b.timestamp || ''));

  const recent = allCalls.slice(-limit);

  let lastDate = '';
  for (const tc of recent) {
    const date = formatDate(tc.timestamp);
    if (date !== lastDate) {
      lastDate = date;
      console.log(chalk.dim(`\n  \u2500\u2500 ${date} \u2500\u2500`));
    }
    const session = sessionMap.get(tc.sessionId);
    printToolCall(tc, detailed, session?.model);
  }

  // Stats summary
  const errorCount = recent.filter((tc) => tc.isError).length;
  const sources = [...new Set(recent.map((tc) => tc.source))];

  console.log('');
  console.log(chalk.dim(`  Showing last ${recent.length} of ${allCalls.length} total tool calls`));
  if (errorCount > 0) {
    console.log(chalk.dim(`  ${errorCount} error(s) in view | Sources: ${sources.join(', ')}`));
  }
  console.log('');
}
