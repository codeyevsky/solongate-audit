import { collectLogs } from './collector.js';
import { runAllChecks } from './checks/index.js';
import { printHeader, printLogSummary, printCompactReport, printScore, printDetailedReport, printFooter, calcScore } from './reporter.js';

const args = process.argv.slice(2);
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
  // Live watch mode — re-scan every 3 seconds
  let lastToolCount = 0;
  let lastSessionCount = 0;

  const refresh = () => {
    const { data, results } = runAudit();

    // Only re-render if data changed
    if (data.totalToolCalls !== lastToolCount || data.sessions.length !== lastSessionCount) {
      lastToolCount = data.totalToolCalls;
      lastSessionCount = data.sessions.length;

      // Clear terminal
      process.stdout.write('\x1b[2J\x1b[H');

      printReport(data, results);
      console.log(`\n  🔴 LIVE — watching for new logs (Ctrl+C to stop)\n`);
    }
  };

  // Initial render
  refresh();

  // Poll every 3 seconds
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
