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

function extractArgSummaryHTML(args: Record<string, unknown>): string {
  if (args.command) return escapeHTML(String(args.command));
  if (args.file_path) return escapeHTML(String(args.file_path));
  if (args.path) return escapeHTML(String(args.path));
  if (args.pattern) return escapeHTML(String(args.pattern));
  if (args.url) return escapeHTML(String(args.url));
  if (args.query) return escapeHTML(String(args.query));
  if (args.old_string) return `<span style="color:#f87171">"${escapeHTML(String(args.old_string).slice(0, 60))}"</span> &rarr; <span style="color:#4ade80">"${escapeHTML(String(args.new_string || '').slice(0, 60))}"</span>`;
  if (args.content) return `<span style="color:#888">[${String(args.content).length} chars]</span>`;
  const keys = Object.keys(args);
  if (keys.length > 0) return escapeHTML(JSON.stringify(args).slice(0, 120));
  return '<span style="color:#555">-</span>';
}

export function exportHTML({ data, results }: ExportPayload): string {
  const { intScore, fixCount } = calcScore(results);
  const allCalls = data.sessions
    .flatMap((s) => s.toolCalls)
    .sort((a, b) => (a.timestamp || '').localeCompare(b.timestamp || ''));
  const sessionMap = new Map(data.sessions.map((s) => [s.id, s]));
  const errorCount = allCalls.filter((tc) => tc.isError).length;

  const statusColor: Record<string, string> = {
    PROTECTED: '#22c55e',
    PARTIAL: '#eab308',
    NOT_PROTECTED: '#ef4444',
  };

  const statusBg: Record<string, string> = {
    PROTECTED: 'rgba(34,197,94,0.1)',
    PARTIAL: 'rgba(234,179,8,0.1)',
    NOT_PROTECTED: 'rgba(239,68,68,0.1)',
  };

  const statusIcon: Record<string, string> = {
    PROTECTED: '&#x2705;',
    PARTIAL: '&#x26A0;&#xFE0F;',
    NOT_PROTECTED: '&#x274C;',
  };

  const sourceColor: Record<string, string> = {
    claude: '#c084fc',
    gemini: '#60a5fa',
    openclaw: '#4ade80',
  };

  const sourceLabel: Record<string, string> = {
    claude: 'Claude',
    gemini: 'Gemini',
    openclaw: 'OpenClaw',
  };

  const auditRows = results
    .sort((a, b) => {
      const order: Record<string, number> = { PROTECTED: 0, PARTIAL: 1, NOT_PROTECTED: 2 };
      return (order[a.status] ?? 2) - (order[b.status] ?? 2);
    })
    .map((r) => `
      <tr>
        <td style="text-align:center">${statusIcon[r.status]}</td>
        <td><span class="code-badge">${escapeHTML(r.code)}</span></td>
        <td class="cat-name">${escapeHTML(r.title)}</td>
        <td><span class="status-pill" style="background:${statusBg[r.status]};color:${statusColor[r.status]}">${r.status.replace(/_/g, ' ')}</span></td>
        <td class="detail-text">${escapeHTML(r.summary)}</td>
        <td class="detail-text">${r.recommendation ? escapeHTML(r.recommendation) : ''}</td>
      </tr>`).join('');

  const toolRows = allCalls.map((tc) => {
    const session = sessionMap.get(tc.sessionId);
    const argSummary = extractArgSummaryHTML(tc.arguments);
    const argFull = escapeHTML(JSON.stringify(tc.arguments, null, 2));
    const resStr = escapeHTML((tc.result || '').slice(0, 500));
    const src = tc.source;
    const time = tc.timestamp ? new Date(tc.timestamp).toLocaleTimeString('en-GB', { hour: '2-digit', minute: '2-digit', second: '2-digit' }) : '';
    const date = tc.timestamp ? new Date(tc.timestamp).toLocaleDateString('en-GB', { day: '2-digit', month: '2-digit', year: '2-digit' }) : '';
    return `
      <tr class="${tc.isError ? 'error-row' : ''}" data-source="${src}">
        <td class="ts"><span class="date-dim">${date}</span> ${time}</td>
        <td><span class="source-badge" style="background:${sourceColor[src] || '#888'}20;color:${sourceColor[src] || '#888'}">${sourceLabel[src] || src}</span></td>
        <td class="tool-name">${escapeHTML(tc.toolName)}${tc.isError ? ' <span class="err-badge">ERR</span>' : ''}</td>
        <td class="arg-cell">${argSummary}${argFull !== '{}' ? `<details><summary class="expand-link">full JSON</summary><pre class="code-block">${argFull}</pre></details>` : ''}</td>
        <td class="result-cell">${resStr ? `<details><summary class="expand-link">${tc.isError ? '<span style="color:#f87171">error</span>' : 'result'}</summary><pre class="code-block">${resStr}</pre></details>` : '<span style="color:#555">-</span>'}</td>
        <td class="meta-cell">${escapeHTML(tc.id.slice(0, 8))}<br><span style="color:#666">${escapeHTML(session?.model || '-')}</span></td>
      </tr>`;
  }).join('');

  const scoreColor = intScore >= 7 ? '#22c55e' : intScore >= 4 ? '#eab308' : '#ef4444';
  const scoreGlow = intScore >= 7 ? '0 0 40px rgba(34,197,94,0.3)' : intScore >= 4 ? '0 0 40px rgba(234,179,8,0.2)' : '0 0 40px rgba(239,68,68,0.3)';

  const html = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>SolonGate Audit Report</title>
<style>
  :root { --bg: #09090b; --surface: #18181b; --surface2: #27272a; --border: #3f3f46; --text: #fafafa; --text2: #a1a1aa; --accent: #60a5fa; }
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; background: var(--bg); color: var(--text); line-height: 1.5; }

  .container { max-width: 1440px; margin: 0 auto; padding: 40px 32px; }

  /* Header */
  .header { display: flex; align-items: center; gap: 16px; margin-bottom: 32px; }
  .logo { width: 40px; height: 40px; background: linear-gradient(135deg, #60a5fa, #a78bfa); border-radius: 10px; display: flex; align-items: center; justify-content: center; font-weight: 900; font-size: 18px; color: #000; }
  .header h1 { font-size: 22px; font-weight: 700; letter-spacing: -0.5px; }
  .header .subtitle { color: var(--text2); font-size: 13px; margin-top: 2px; }

  /* Stats Row */
  .stats-row { display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 16px; margin-bottom: 32px; }
  .stat-card { background: var(--surface); border: 1px solid var(--border); border-radius: 12px; padding: 20px; }
  .stat-label { font-size: 11px; color: var(--text2); text-transform: uppercase; letter-spacing: 1.5px; font-weight: 600; }
  .stat-value { font-size: 28px; font-weight: 800; margin-top: 6px; letter-spacing: -1px; }
  .stat-sub { font-size: 12px; color: var(--text2); margin-top: 2px; }

  /* Score */
  .score-section { background: var(--surface); border: 1px solid var(--border); border-radius: 16px; padding: 32px; margin-bottom: 32px; display: flex; align-items: center; gap: 32px; box-shadow: ${scoreGlow}; }
  .score-ring { width: 120px; height: 120px; position: relative; flex-shrink: 0; }
  .score-ring svg { width: 100%; height: 100%; transform: rotate(-90deg); }
  .score-ring circle { fill: none; stroke-width: 8; }
  .score-ring .bg { stroke: var(--surface2); }
  .score-ring .fg { stroke: ${scoreColor}; stroke-linecap: round; stroke-dasharray: ${(intScore / 10) * 314} 314; transition: stroke-dasharray 1s ease; }
  .score-num { position: absolute; top: 50%; left: 50%; transform: translate(-50%, -50%); font-size: 32px; font-weight: 900; color: ${scoreColor}; }
  .score-info h3 { font-size: 18px; margin-bottom: 4px; }
  .score-info p { color: var(--text2); font-size: 14px; }

  /* Section */
  .section { margin-bottom: 32px; }
  .section-title { font-size: 16px; font-weight: 700; margin-bottom: 16px; display: flex; align-items: center; gap: 8px; }
  .section-count { background: var(--surface2); color: var(--text2); font-size: 11px; padding: 2px 8px; border-radius: 10px; font-weight: 600; }

  /* Tables */
  table { width: 100%; border-collapse: separate; border-spacing: 0; background: var(--surface); border: 1px solid var(--border); border-radius: 12px; overflow: hidden; }
  th { text-align: left; padding: 12px 16px; background: var(--surface2); font-size: 11px; text-transform: uppercase; letter-spacing: 1px; color: var(--text2); font-weight: 600; border-bottom: 1px solid var(--border); }
  td { padding: 10px 16px; border-bottom: 1px solid #27272a; font-size: 13px; vertical-align: top; }
  tr:last-child td { border-bottom: none; }
  tbody tr:hover { background: rgba(96,165,250,0.04); }
  .error-row { background: rgba(239,68,68,0.06); }
  .error-row:hover { background: rgba(239,68,68,0.1); }

  /* Badges */
  .code-badge { background: var(--surface2); color: var(--accent); padding: 2px 8px; border-radius: 4px; font-family: 'JetBrains Mono', monospace; font-size: 12px; font-weight: 600; }
  .status-pill { padding: 3px 10px; border-radius: 20px; font-size: 11px; font-weight: 700; text-transform: uppercase; letter-spacing: 0.5px; white-space: nowrap; }
  .source-badge { padding: 2px 8px; border-radius: 4px; font-size: 11px; font-weight: 600; white-space: nowrap; }
  .err-badge { background: rgba(239,68,68,0.2); color: #f87171; padding: 1px 6px; border-radius: 3px; font-size: 10px; font-weight: 700; }
  .cat-name { font-weight: 600; }
  .detail-text { font-size: 12px; color: var(--text2); max-width: 300px; }

  /* Tool call table specifics */
  .ts { white-space: nowrap; font-family: 'JetBrains Mono', monospace; font-size: 12px; color: var(--text2); }
  .date-dim { color: #52525b; }
  .tool-name { font-weight: 600; font-family: 'JetBrains Mono', monospace; font-size: 12px; white-space: nowrap; }
  .arg-cell { font-family: 'JetBrains Mono', monospace; font-size: 12px; max-width: 400px; word-break: break-all; }
  .result-cell { max-width: 200px; }
  .meta-cell { font-family: 'JetBrains Mono', monospace; font-size: 11px; color: var(--text2); white-space: nowrap; }

  /* Expandable */
  .expand-link { cursor: pointer; color: var(--accent); font-size: 11px; opacity: 0.7; margin-top: 4px; }
  .expand-link:hover { opacity: 1; }
  .code-block { background: var(--bg); padding: 10px 12px; border-radius: 6px; margin-top: 6px; font-size: 11px; max-height: 250px; overflow: auto; white-space: pre-wrap; word-break: break-all; border: 1px solid var(--border); color: var(--text2); }

  /* Filter Bar */
  .filter-bar { display: flex; gap: 8px; margin-bottom: 16px; flex-wrap: wrap; }
  .filter-bar input, .filter-bar select { background: var(--surface); border: 1px solid var(--border); color: var(--text); padding: 8px 14px; border-radius: 8px; font-size: 13px; outline: none; transition: border-color 0.2s; }
  .filter-bar input:focus, .filter-bar select:focus { border-color: var(--accent); }
  .filter-bar input { flex: 1; min-width: 240px; }

  /* Buttons */
  .btn-group { position: fixed; bottom: 24px; right: 24px; display: flex; gap: 8px; z-index: 100; }
  .btn { border: none; padding: 10px 20px; border-radius: 8px; font-weight: 700; cursor: pointer; font-size: 13px; transition: transform 0.1s, box-shadow 0.2s; }
  .btn:hover { transform: translateY(-1px); }
  .btn:active { transform: translateY(0); }
  .btn-primary { background: var(--accent); color: #000; box-shadow: 0 4px 12px rgba(96,165,250,0.3); }
  .btn-secondary { background: var(--surface2); color: var(--text); border: 1px solid var(--border); }

  /* Footer */
  .footer { text-align: center; margin-top: 48px; padding: 24px; border-top: 1px solid var(--border); }
  .footer a { color: var(--accent); text-decoration: none; font-weight: 600; }
  .footer p { color: #52525b; font-size: 12px; margin-top: 4px; }

  /* Scroll to top */
  #scrollTop { display: none; position: fixed; bottom: 24px; left: 24px; background: var(--surface2); border: 1px solid var(--border); color: var(--text); width: 40px; height: 40px; border-radius: 8px; cursor: pointer; font-size: 18px; z-index: 100; }

  @media print {
    body { background: #fff; color: #000; }
    .container { padding: 16px; }
    .stat-card, .score-section, table { background: #fff; border-color: #ddd; }
    th { background: #f5f5f5; color: #333; border-color: #ddd; }
    td { border-color: #eee; }
    .code-block { background: #f8f8f8; border-color: #ddd; }
    tbody tr:hover { background: transparent; }
    .error-row { background: #fff5f5; }
    .btn-group, .filter-bar, #scrollTop { display: none !important; }
    @page { size: A4 landscape; margin: 8mm; }
  }
</style>
</head>
<body>
<div class="container">

<div class="header">
  <div class="logo">S</div>
  <div>
    <h1>SolonGate Security Audit</h1>
    <div class="subtitle">OWASP Agentic Top 10 &mdash; ${new Date().toLocaleDateString('en-GB', { day: '2-digit', month: 'long', year: 'numeric' })}</div>
  </div>
</div>

<div class="stats-row">
  <div class="stat-card">
    <div class="stat-label">AI Tools</div>
    <div class="stat-value">${data.sources.length}</div>
    <div class="stat-sub">${data.sources.join(', ') || 'None detected'}</div>
  </div>
  <div class="stat-card">
    <div class="stat-label">Sessions</div>
    <div class="stat-value">${data.sessions.length}</div>
    <div class="stat-sub">${data.timeRange ? new Date(data.timeRange.from).toLocaleDateString('en-GB') + ' &ndash; ' + new Date(data.timeRange.to).toLocaleDateString('en-GB') : 'N/A'}</div>
  </div>
  <div class="stat-card">
    <div class="stat-label">Tool Calls</div>
    <div class="stat-value">${data.totalToolCalls.toLocaleString()}</div>
    <div class="stat-sub">${errorCount > 0 ? errorCount + ' error' + (errorCount > 1 ? 's' : '') : 'No errors'}</div>
  </div>
  <div class="stat-card">
    <div class="stat-label">Issues Found</div>
    <div class="stat-value" style="color:${fixCount > 0 ? '#ef4444' : '#22c55e'}">${fixCount}</div>
    <div class="stat-sub">${fixCount > 0 ? 'critical categories' : 'All clear'}</div>
  </div>
</div>

<div class="score-section">
  <div class="score-ring">
    <svg viewBox="0 0 120 120">
      <circle class="bg" cx="60" cy="60" r="50" />
      <circle class="fg" cx="60" cy="60" r="50" />
    </svg>
    <div class="score-num">${intScore}</div>
  </div>
  <div class="score-info">
    <h3>Security Score: ${intScore}/10</h3>
    <p>${intScore >= 7 ? 'Good protection level. Keep monitoring for changes.' : intScore >= 4 ? 'Moderate protection. Several categories need attention.' : 'Low protection. Critical security gaps detected across multiple categories.'}</p>
    ${fixCount > 0 ? `<p style="margin-top:8px"><a href="https://solongate.com" style="color:${scoreColor};text-decoration:none;font-weight:600">Fix ${fixCount} issue${fixCount > 1 ? 's' : ''} &rarr; solongate.com</a></p>` : ''}
  </div>
</div>

<div class="section">
  <div class="section-title">Audit Results <span class="section-count">${results.length} checks</span></div>
  <table>
    <thead><tr><th style="width:40px"></th><th>Code</th><th>Category</th><th>Status</th><th>Details</th><th>Recommendation</th></tr></thead>
    <tbody>${auditRows}</tbody>
  </table>
</div>

<div class="section">
  <div class="section-title">Tool Call Log <span class="section-count">${allCalls.length.toLocaleString()} calls</span></div>
  <div class="filter-bar">
    <input type="text" id="searchInput" placeholder="Search tool name, arguments, source..." oninput="filterTable()">
    <select id="sourceFilter" onchange="filterTable()">
      <option value="">All Sources</option>
      <option value="claude">Claude</option>
      <option value="gemini">Gemini</option>
      <option value="openclaw">OpenClaw</option>
    </select>
    <select id="errorFilter" onchange="filterTable()">
      <option value="">All Status</option>
      <option value="error">Errors Only</option>
      <option value="success">Success Only</option>
    </select>
  </div>
  <table id="logTable">
    <thead><tr><th>Time</th><th>Source</th><th>Tool</th><th>Arguments</th><th>Result</th><th>Meta</th></tr></thead>
    <tbody>${toolRows}</tbody>
  </table>
</div>

<div class="btn-group">
  <button class="btn btn-secondary" onclick="scrollTo({top:0,behavior:'smooth'})">&#x2191; Top</button>
  <button class="btn btn-primary" onclick="window.print()">&#x1F4E4; Export PDF</button>
</div>

<div class="footer">
  <a href="https://solongate.com">solongate.com</a>
  <p>AI Agent Security &mdash; OWASP Agentic Top 10 Audit</p>
</div>

</div>

<script>
function filterTable() {
  const search = document.getElementById('searchInput').value.toLowerCase();
  const source = document.getElementById('sourceFilter').value;
  const error = document.getElementById('errorFilter').value;
  const rows = document.querySelectorAll('#logTable tbody tr');
  let visible = 0;
  rows.forEach(row => {
    const text = row.textContent.toLowerCase();
    const rowSource = row.getAttribute('data-source') || '';
    const isError = row.classList.contains('error-row');
    const matchSearch = !search || text.includes(search);
    const matchSource = !source || rowSource === source;
    const matchError = !error || (error === 'error' && isError) || (error === 'success' && !isError);
    const show = matchSearch && matchSource && matchError;
    row.style.display = show ? '' : 'none';
    if (show) visible++;
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
