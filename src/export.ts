import { writeFileSync } from 'fs';
import { resolve } from 'path';
import chalk from 'chalk';
import type { AuditData, CheckResult } from './types.js';
import { calcScore } from './reporter.js';

interface ExportPayload {
  data: AuditData;
  results: CheckResult[];
}

function getFilePath(ext: string): string {
  return resolve(process.cwd(), `solongate-audit-report.${ext}`);
}

// ── JSON Export ──

export function exportJSON({ data, results }: ExportPayload): string {
  const { intScore } = calcScore(results);
  const allCalls = data.sessions.flatMap((s) =>
    s.toolCalls.map((tc) => ({
      ...tc,
      model: s.model || null,
    }))
  );

  const payload = {
    generatedAt: new Date().toISOString(),
    score: intScore,
    maxScore: 10,
    summary: {
      sources: data.sources,
      sessions: data.sessions.length,
      totalToolCalls: data.totalToolCalls,
      timeRange: data.timeRange,
    },
    auditResults: results.map((r) => ({
      code: r.code,
      title: r.title,
      status: r.status,
      summary: r.summary,
      details: r.details,
      recommendation: r.recommendation || null,
      evidence: r.evidence,
    })),
    sessions: data.sessions.map((s) => ({
      id: s.id,
      source: s.source,
      model: s.model || null,
      startTime: s.startTime,
      endTime: s.endTime || null,
      filePath: s.filePath,
      toolCallCount: s.toolCalls.length,
    })),
    toolCalls: allCalls.sort((a, b) => (a.timestamp || '').localeCompare(b.timestamp || '')),
  };

  const filePath = getFilePath('json');
  writeFileSync(filePath, JSON.stringify(payload, null, 2), 'utf-8');
  return filePath;
}

// ── CSV Export ──

function escapeCSV(value: unknown): string {
  const str = String(value ?? '');
  if (str.includes(',') || str.includes('"') || str.includes('\n') || str.includes('\r')) {
    return '"' + str.replace(/"/g, '""') + '"';
  }
  return str;
}

export function exportCSV({ data }: ExportPayload): string {
  const headers = ['timestamp', 'source', 'sessionId', 'model', 'toolCallId', 'toolName', 'arguments', 'result', 'isError'];
  const rows: string[] = [headers.join(',')];

  const sessionMap = new Map(data.sessions.map((s) => [s.id, s]));

  const allCalls = data.sessions
    .flatMap((s) => s.toolCalls)
    .sort((a, b) => (a.timestamp || '').localeCompare(b.timestamp || ''));

  for (const tc of allCalls) {
    const session = sessionMap.get(tc.sessionId);
    rows.push([
      escapeCSV(tc.timestamp),
      escapeCSV(tc.source),
      escapeCSV(tc.sessionId),
      escapeCSV(session?.model || ''),
      escapeCSV(tc.id),
      escapeCSV(tc.toolName),
      escapeCSV(JSON.stringify(tc.arguments)),
      escapeCSV(tc.result || ''),
      escapeCSV(tc.isError ? 'true' : 'false'),
    ].join(','));
  }

  const filePath = getFilePath('csv');
  writeFileSync(filePath, rows.join('\n'), 'utf-8');
  return filePath;
}

// ── HTML Export ──

function escapeHTML(str: string): string {
  return str.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

export function exportHTML({ data, results }: ExportPayload): string {
  const { intScore } = calcScore(results);
  const allCalls = data.sessions
    .flatMap((s) => s.toolCalls)
    .sort((a, b) => (a.timestamp || '').localeCompare(b.timestamp || ''));
  const sessionMap = new Map(data.sessions.map((s) => [s.id, s]));

  const statusColor: Record<string, string> = {
    PROTECTED: '#22c55e',
    PARTIAL: '#eab308',
    NOT_PROTECTED: '#ef4444',
  };

  const statusIcon: Record<string, string> = {
    PROTECTED: '&#x2705;',
    PARTIAL: '&#x26A0;&#xFE0F;',
    NOT_PROTECTED: '&#x274C;',
  };

  const auditRows = results
    .sort((a, b) => {
      const order: Record<string, number> = { PROTECTED: 0, PARTIAL: 1, NOT_PROTECTED: 2 };
      return (order[a.status] ?? 2) - (order[b.status] ?? 2);
    })
    .map((r) => `
      <tr>
        <td>${statusIcon[r.status]}</td>
        <td><strong>${escapeHTML(r.code)}</strong></td>
        <td>${escapeHTML(r.title)}</td>
        <td style="color:${statusColor[r.status]};font-weight:700">${r.status.replace('_', ' ')}</td>
        <td style="font-size:12px;color:#888">${escapeHTML(r.summary)}</td>
      </tr>`).join('');

  const toolRows = allCalls.map((tc) => {
    const session = sessionMap.get(tc.sessionId);
    const argStr = escapeHTML(JSON.stringify(tc.arguments, null, 2));
    const resStr = escapeHTML(tc.result || '');
    return `
      <tr class="${tc.isError ? 'error-row' : ''}">
        <td class="ts">${escapeHTML(tc.timestamp || '')}</td>
        <td>${escapeHTML(tc.source)}</td>
        <td>${escapeHTML(tc.sessionId.slice(0, 8))}</td>
        <td>${escapeHTML(session?.model || '-')}</td>
        <td>${escapeHTML(tc.id.slice(0, 8))}</td>
        <td><strong>${escapeHTML(tc.toolName)}</strong></td>
        <td><details><summary>View</summary><pre>${argStr}</pre></details></td>
        <td><details><summary>${tc.isError ? '<span style="color:red">Error</span>' : 'View'}</summary><pre>${resStr}</pre></details></td>
      </tr>`;
  }).join('');

  const scoreColor = intScore >= 7 ? '#22c55e' : intScore >= 4 ? '#eab308' : '#ef4444';

  const html = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>SolonGate Audit Report</title>
<style>
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #0a0a0a; color: #e5e5e5; padding: 32px; max-width: 1400px; margin: 0 auto; }
  h1 { font-size: 24px; margin-bottom: 4px; }
  .subtitle { color: #888; font-size: 14px; margin-bottom: 24px; }
  .meta { display: flex; gap: 24px; margin-bottom: 24px; flex-wrap: wrap; }
  .meta-item { background: #1a1a1a; border: 1px solid #333; border-radius: 8px; padding: 16px 20px; min-width: 160px; }
  .meta-label { font-size: 12px; color: #888; text-transform: uppercase; letter-spacing: 1px; }
  .meta-value { font-size: 24px; font-weight: 700; margin-top: 4px; }
  .score-card { background: #1a1a1a; border: 2px solid ${scoreColor}; border-radius: 12px; padding: 24px; margin-bottom: 32px; text-align: center; }
  .score-num { font-size: 64px; font-weight: 800; color: ${scoreColor}; }
  .score-label { font-size: 14px; color: #888; }
  table { width: 100%; border-collapse: collapse; margin-bottom: 32px; }
  th { text-align: left; padding: 10px 12px; border-bottom: 2px solid #333; font-size: 12px; text-transform: uppercase; letter-spacing: 1px; color: #888; }
  td { padding: 8px 12px; border-bottom: 1px solid #222; font-size: 13px; vertical-align: top; }
  tr:hover { background: #1a1a1a; }
  .error-row { background: #1c0a0a; }
  .error-row:hover { background: #2a1010; }
  .ts { white-space: nowrap; font-family: monospace; font-size: 12px; }
  details summary { cursor: pointer; color: #60a5fa; font-size: 12px; }
  details pre { background: #111; padding: 8px; border-radius: 4px; margin-top: 4px; font-size: 11px; max-height: 300px; overflow: auto; white-space: pre-wrap; word-break: break-all; }
  h2 { font-size: 18px; margin: 32px 0 16px; border-bottom: 1px solid #333; padding-bottom: 8px; }
  .filter-bar { margin-bottom: 16px; display: flex; gap: 8px; flex-wrap: wrap; }
  .filter-bar input, .filter-bar select { background: #1a1a1a; border: 1px solid #333; color: #e5e5e5; padding: 6px 12px; border-radius: 4px; font-size: 13px; }
  .filter-bar input { flex: 1; min-width: 200px; }
  .print-btn { position: fixed; bottom: 24px; right: 24px; background: #60a5fa; color: #000; border: none; padding: 12px 24px; border-radius: 8px; font-weight: 700; cursor: pointer; font-size: 14px; z-index: 100; }
  .print-btn:hover { background: #93c5fd; }
  .brand { text-align: center; margin-top: 48px; padding: 24px; border-top: 1px solid #222; color: #555; font-size: 13px; }
  .brand a { color: #60a5fa; text-decoration: none; }
  @media print {
    body { background: #fff; color: #000; padding: 16px; }
    .meta-item { border-color: #ddd; background: #f5f5f5; }
    .score-card { background: #f5f5f5; }
    th { border-color: #ccc; color: #333; }
    td { border-color: #eee; }
    tr:hover, .error-row:hover { background: transparent; }
    .error-row { background: #fff0f0; }
    details pre { background: #f5f5f5; }
    .print-btn { display: none; }
    .filter-bar { display: none; }
    @page { size: A4 landscape; margin: 10mm; }
  }
</style>
</head>
<body>
<h1>SolonGate Security Audit</h1>
<p class="subtitle">OWASP Agentic Top 10 &mdash; Generated ${new Date().toLocaleString()}</p>

<div class="meta">
  <div class="meta-item"><div class="meta-label">AI Tools</div><div class="meta-value">${data.sources.length}</div></div>
  <div class="meta-item"><div class="meta-label">Sessions</div><div class="meta-value">${data.sessions.length}</div></div>
  <div class="meta-item"><div class="meta-label">Tool Calls</div><div class="meta-value">${data.totalToolCalls.toLocaleString()}</div></div>
  <div class="meta-item"><div class="meta-label">Period</div><div class="meta-value" style="font-size:14px">${data.timeRange ? new Date(data.timeRange.from).toLocaleDateString() + ' &mdash; ' + new Date(data.timeRange.to).toLocaleDateString() : 'N/A'}</div></div>
</div>

<div class="score-card">
  <div class="score-num">${intScore}/10</div>
  <div class="score-label">Security Score</div>
</div>

<h2>Audit Results</h2>
<table>
  <thead><tr><th></th><th>Code</th><th>Category</th><th>Status</th><th>Details</th></tr></thead>
  <tbody>${auditRows}</tbody>
</table>

<h2>Tool Call Log (${allCalls.length.toLocaleString()} calls)</h2>
<div class="filter-bar">
  <input type="text" id="searchInput" placeholder="Filter by tool name, arguments, source..." oninput="filterTable()">
  <select id="sourceFilter" onchange="filterTable()">
    <option value="">All Sources</option>
    <option value="claude">Claude</option>
    <option value="gemini">Gemini</option>
    <option value="openclaw">OpenClaw</option>
  </select>
  <select id="errorFilter" onchange="filterTable()">
    <option value="">All</option>
    <option value="error">Errors Only</option>
    <option value="success">Success Only</option>
  </select>
</div>
<table id="logTable">
  <thead><tr><th>Timestamp</th><th>Source</th><th>Session</th><th>Model</th><th>Call ID</th><th>Tool</th><th>Arguments</th><th>Result</th></tr></thead>
  <tbody>${toolRows}</tbody>
</table>

<button class="print-btn" onclick="window.print()">&#x1F4E4; Export PDF</button>

<div class="brand">
  Generated by <a href="https://solongate.com">SolonGate</a> &mdash; AI Agent Security
</div>

<script>
function filterTable() {
  const search = document.getElementById('searchInput').value.toLowerCase();
  const source = document.getElementById('sourceFilter').value;
  const error = document.getElementById('errorFilter').value;
  const rows = document.querySelectorAll('#logTable tbody tr');
  rows.forEach(row => {
    const text = row.textContent.toLowerCase();
    const isError = row.classList.contains('error-row');
    const matchSearch = !search || text.includes(search);
    const matchSource = !source || text.includes(source);
    const matchError = !error || (error === 'error' && isError) || (error === 'success' && !isError);
    row.style.display = matchSearch && matchSource && matchError ? '' : 'none';
  });
}
</script>
</body>
</html>`;

  const filePath = getFilePath('html');
  writeFileSync(filePath, html, 'utf-8');
  return filePath;
}

// ── PDF Export (HTML with auto-print) ──

export function exportPDF(payload: ExportPayload): string {
  const { data, results } = payload;
  const htmlPath = exportHTML(payload);

  // Create a separate PDF-ready HTML that auto-triggers print dialog
  const pdfHtml = `<!DOCTYPE html>
<html><head>
<meta charset="UTF-8">
<meta http-equiv="refresh" content="0;url=${htmlPath.replace(/\\/g, '/')}">
</head>
<body>
<p>Opening report... If not redirected, <a href="${htmlPath.replace(/\\/g, '/')}">click here</a> and press Ctrl+P to save as PDF.</p>
</body></html>`;

  const filePath = getFilePath('pdf.html');
  writeFileSync(filePath, pdfHtml, 'utf-8');
  return filePath;
}

// ── Export all ──

export function exportAll(payload: ExportPayload): string[] {
  return [
    exportJSON(payload),
    exportCSV(payload),
    exportHTML(payload),
    exportPDF(payload),
  ];
}

// ── Export dispatcher ──

export function runExport(format: string, payload: ExportPayload): void {
  console.log('');

  if (format === 'all') {
    const files = exportAll(payload);
    for (const f of files) {
      console.log(`  ${chalk.green('\u2714')} ${f}`);
    }
  } else {
    let filePath: string;
    switch (format) {
      case 'json': filePath = exportJSON(payload); break;
      case 'csv': filePath = exportCSV(payload); break;
      case 'html': filePath = exportHTML(payload); break;
      case 'pdf': filePath = exportPDF(payload); break;
      default:
        console.log(chalk.red(`  Unknown format: ${format}`));
        console.log(chalk.dim('  Supported: json, csv, html, pdf, all'));
        process.exit(1);
    }
    console.log(`  ${chalk.green('\u2714')} Exported: ${filePath}`);
  }

  console.log('');
}
