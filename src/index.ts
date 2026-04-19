import { collectLogs } from './collector.js';
import { runAllChecks } from './checks/index.js';
import { printHeader, printLogSummary, printCompactReport, printScore, printDetailedReport, printFooter, calcScore, printLogs, printToolCall } from './reporter.js';
import { addDir, removeDir, listDirs, searchLogs } from './config.js';
import { Spinner } from './spinner.js';
import chalk from 'chalk';

const args = process.argv.slice(2);

// ── Config commands ──
if (args.includes('--add-dir')) {
  const idx = args.indexOf('--add-dir');
  const dir = args[idx + 1];
  if (!dir) { console.log('  Usage: solongate-audit --add-dir <path>'); process.exit(1); }
  addDir(dir);
  process.exit(0);
}

if (args.includes('--remove-dir')) {
  const idx = args.indexOf('--remove-dir');
  const dir = args[idx + 1];
  if (!dir) { console.log('  Usage: solongate-audit --remove-dir <path>'); process.exit(1); }
  removeDir(dir);
  process.exit(0);
}

if (args.includes('--list-dirs')) { listDirs(); process.exit(0); }
if (args.includes('--search')) { searchLogs(); process.exit(0); }

if (args.includes('--help') || args.includes('-h')) {
  console.log(`
  solongate-audit — AI agent audit log tool

  Usage:
    npx solongate-audit                 Scan logs and show report
    npx solongate-audit --detailed      Show detailed analysis per category
    npx solongate-audit --logs          Show recent tool calls (last 50)
    npx solongate-audit --logs 100      Show last N tool calls
    npx solongate-audit --watch         Live monitoring with log feed
    npx solongate-audit --json          Machine-readable JSON output

  Log directories:
    npx solongate-audit --search        Search system for AI tool logs
    npx solongate-audit --list-dirs     Show all log directories
    npx solongate-audit --add-dir <path>    Add a custom log directory
    npx solongate-audit --remove-dir <path> Remove a custom log directory

  Config: ~/.solongate-audit/config.json
`);
  process.exit(0);
}

// ── Audit ──
const showDetailed = args.includes('--detailed') || args.includes('-d');
const showJson = args.includes('--json');
const showWatch = args.includes('--watch') || args.includes('-w');
const showLogs = args.includes('--logs') || args.includes('-l');

function getLogLimit(): number {
  const idx = args.indexOf('--logs') !== -1 ? args.indexOf('--logs') : args.indexOf('-l');
  if (idx !== -1 && args[idx + 1] && !args[idx + 1].startsWith('-')) {
    return parseInt(args[idx + 1], 10) || 50;
  }
  return 50;
}

function runAudit(silent = false) {
  const spinner = silent ? null : new Spinner('Scanning AI tool logs...');
  spinner?.start();

  const data = collectLogs();
  spinner?.update('Running OWASP Agentic Top 10 checks...');

  const results = runAllChecks(data);
  const { intScore } = calcScore(results);

  spinner?.stop(`Scanned ${data.totalToolCalls} tool calls across ${data.sessions.length} sessions`);

  return { data, results, intScore };
}

function printReport(data: ReturnType<typeof collectLogs>, results: ReturnType<typeof runAllChecks>) {
  printHeader();
  printLogSummary(data);
  printCompactReport(results);
  printScore(results);
  if (showDetailed) {
    printDetailedReport(results);
    printFooter(results);
  }
}

if (showWatch) {
  // Live watch mode — show summary + live log feed
  let lastToolCount = 0;
  let lastSessionCount = 0;
  let seenIds = new Set<string>();

  const init = () => {
    const { data, results } = runAudit();
    lastToolCount = data.totalToolCalls;
    lastSessionCount = data.sessions.length;

    // Track all existing tool call IDs
    for (const tc of data.sessions.flatMap((s) => s.toolCalls)) {
      seenIds.add(tc.id + tc.timestamp);
    }

    process.stdout.write('\x1b[2J\x1b[H');
    printReport(data, results);

    // Show last 10 tool calls as initial context
    const allCalls = data.sessions
      .flatMap((s) => s.toolCalls)
      .sort((a, b) => (a.timestamp || '').localeCompare(b.timestamp || ''));
    const last10 = allCalls.slice(-10);

    console.log('');
    console.log(chalk.bold('  Live Log Feed'));
    console.log(chalk.dim('  ' + '\u2500'.repeat(80)));
    console.log(chalk.dim('  Time     Source Tool              Arguments'));
    console.log(chalk.dim('  ' + '\u2500'.repeat(80)));

    for (const tc of last10) {
      printToolCall(tc, true);
    }

    console.log('');
    console.log(chalk.dim('  Waiting for new tool calls...'));
  };

  init();

  // Poll for new logs (silent — no spinner during polling)
  setInterval(() => {
    const { data, results } = runAudit(true);

    if (data.totalToolCalls !== lastToolCount || data.sessions.length !== lastSessionCount) {
      // Find new tool calls
      const newCalls = data.sessions
        .flatMap((s) => s.toolCalls)
        .filter((tc) => !seenIds.has(tc.id + tc.timestamp))
        .sort((a, b) => (a.timestamp || '').localeCompare(b.timestamp || ''));

      if (newCalls.length > 0) {
        // Clear "Waiting..." line and print new calls
        process.stdout.write('\x1b[1A\x1b[2K');

        for (const tc of newCalls) {
          seenIds.add(tc.id + tc.timestamp);
          printToolCall(tc, true);
        }

        // Update summary line
        const { intScore } = calcScore(results);
        const errorCount = data.sessions.flatMap((s) => s.toolCalls).filter((tc) => tc.isError).length;
        console.log('');
        console.log(chalk.dim(`  ${data.totalToolCalls} calls | ${data.sessions.length} sessions | ${errorCount} errors | Score: ${intScore}/10 | LIVE`));
      }

      lastToolCount = data.totalToolCalls;
      lastSessionCount = data.sessions.length;
    }
  }, 2000);

} else if (showLogs) {
  const { data } = runAudit();
  printHeader();
  printLogSummary(data);
  printLogs(data, getLogLimit());

} else {
  const { data, results, intScore } = runAudit(showJson);

  if (showJson) {
    console.log(JSON.stringify({
      score: intScore,
      maxScore: 10,
      results,
      summary: {
        sources: data.sources,
        sessions: data.sessions.length,
        totalToolCalls: data.totalToolCalls,
        timeRange: data.timeRange,
      },
    }, null, 2));
  } else {
    printReport(data, results);
  }

  process.exit(intScore >= 7 ? 0 : 1);
}
