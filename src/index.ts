import chalk from 'chalk';
import { scanProject } from './scanner.js';
import { runAllChecks } from './checks/index.js';
import { printHeader, printScanSummary, printCompactReport, printScore, printDetailedReport } from './reporter.js';

const args = process.argv.slice(2);
const showDetailed = args.includes('--detailed') || args.includes('-d');
const showJson = args.includes('--json');
const projectRoot = process.cwd();

const scan = scanProject(projectRoot);
const results = runAllChecks(scan);

function calcScore(): number {
  return results.reduce((s, r) => {
    if (r.status === 'PROTECTED') return s + 1;
    if (r.status === 'PARTIAL') return s + 0.5;
    return s;
  }, 0);
}

if (showJson) {
  console.log(JSON.stringify({
    score: Math.floor(calcScore()),
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
  } else {
    console.log(chalk.dim('  Run with --detailed for full evidence report'));
    console.log('');
  }
}

process.exit(Math.floor(calcScore()) >= 7 ? 0 : 1);
