import { scanProject } from './scanner.js';
import { runAllChecks } from './checks/index.js';
import { printHeader, printScanSummary, printCompactReport, printScore, printDetailedReport, printFooter, calcScore } from './reporter.js';

const args = process.argv.slice(2);
const showDetailed = args.includes('--detailed') || args.includes('-d');
const showJson = args.includes('--json');
const projectRoot = process.cwd();

const scan = scanProject(projectRoot);
const results = runAllChecks(scan);
const { intScore } = calcScore(results);

if (showJson) {
  console.log(JSON.stringify({
    score: intScore,
    maxScore: 10,
    results,
    scan: {
      projectRoot: scan.projectRoot,
      aiTools: scan.aiTools,
      servers: scan.servers.map((s) => ({ name: s.name, proxy: s.proxy, isDangerous: s.isDangerous })),
    },
  }, null, 2));
} else {
  printHeader();
  printScanSummary(scan);
  printCompactReport(results);
  printScore(results);
  if (showDetailed) {
    printDetailedReport(results);
    printFooter(results);
  }
}

process.exit(intScore >= 7 ? 0 : 1);
