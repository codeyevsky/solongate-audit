import { collectLogs } from './collector.js';
import { runAllChecks } from './checks/index.js';
import { printHeader, printLogSummary, printCompactReport, printScore, printDetailedReport, printFooter, calcScore } from './reporter.js';
import { addDir, removeDir, listDirs, searchLogs } from './config.js';

const args = process.argv.slice(2);

// ── Config commands ──
if (args.includes('--add-dir')) {
  const idx = args.indexOf('--add-dir');
  const dir = args[idx + 1];
  if (!dir) {
    console.log('  Usage: solongate-audit --add-dir <path>');
    process.exit(1);
  }
  addDir(dir);
  process.exit(0);
}

if (args.includes('--remove-dir')) {
  const idx = args.indexOf('--remove-dir');
  const dir = args[idx + 1];
  if (!dir) {
    console.log('  Usage: solongate-audit --remove-dir <path>');
    process.exit(1);
  }
  removeDir(dir);
  process.exit(0);
}

if (args.includes('--list-dirs')) {
  listDirs();
  process.exit(0);
}

if (args.includes('--search')) {
  searchLogs();
  process.exit(0);
}

if (args.includes('--help') || args.includes('-h')) {
  console.log(`
  solongate-audit — AI agent audit log tool

  Usage:
    npx solongate-audit                 Scan logs and show report
    npx solongate-audit --detailed      Show detailed analysis per category
    npx solongate-audit --watch         Live monitoring (re-scans every 3s)
    npx solongate-audit --json          Machine-readable JSON output

  Log directories:
    npx solongate-audit --search        Search system for AI tool logs
    npx solongate-audit --list-dirs     Show all log directories (default + custom)
    npx solongate-audit --add-dir <path>    Add a custom log directory
    npx solongate-audit --remove-dir <path> Remove a custom log directory

  Default log locations:
    Claude Code  ~/.claude/projects/
    Gemini CLI   ~/.gemini/tmp/
    OpenClaw     ~/.openclaw/agents/main/sessions/

  Config: ~/.solongate-audit/config.json
`);
  process.exit(0);
}

// ── Audit ──
const showDetailed = args.includes('--detailed') || args.includes('-d');
const showJson = args.includes('--json');
const showWatch = args.includes('--watch') || args.includes('-w');

function runAudit() {
  const data = collectLogs();
  const results = runAllChecks(data);
  const { intScore } = calcScore(results);
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
  let lastToolCount = 0;
  let lastSessionCount = 0;

  const refresh = () => {
    const { data, results } = runAudit();

    if (data.totalToolCalls !== lastToolCount || data.sessions.length !== lastSessionCount) {
      lastToolCount = data.totalToolCalls;
      lastSessionCount = data.sessions.length;

      process.stdout.write('\x1b[2J\x1b[H');
      printReport(data, results);
      console.log(`\n  LIVE — watching for new logs (Ctrl+C to stop)\n`);
    }
  };

  refresh();
  setInterval(refresh, 3000);
} else {
  const { data, results, intScore } = runAudit();

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
