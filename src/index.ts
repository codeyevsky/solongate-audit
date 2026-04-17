import { collectLogs } from './collector.js';
import { runAllChecks } from './checks/index.js';
import { printHeader, printLogSummary, printCompactReport, printScore, printDetailedReport, printFooter, calcScore } from './reporter.js';

const args = process.argv.slice(2);
const showDetailed = args.includes('--detailed') || args.includes('-d');
const showJson = args.includes('--json');

const data = collectLogs();
const results = runAllChecks(data);
const { intScore } = calcScore(results);

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
  printHeader();
  printLogSummary(data);
  printCompactReport(results);
  printScore(results);
  if (showDetailed) {
    printDetailedReport(results);
    printFooter(results);
  }
}

process.exit(intScore >= 7 ? 0 : 1);
