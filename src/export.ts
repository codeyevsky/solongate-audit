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
  const { intScore, fixCount } = calcScore(results);
  const allCalls = data.sessions
    .flatMap((s) => s.toolCalls)
    .sort((a, b) => (b.timestamp || '').localeCompare(a.timestamp || ''));
  const sessionMap = new Map(data.sessions.map((s) => [s.id, s]));
  const errorCount = allCalls.filter((tc) => tc.isError).length;

  const statusIcon: Record<string, string> = {
    PROTECTED: '&#x2705;',
    PARTIAL: '&#x26A0;&#xFE0F;',
    NOT_PROTECTED: '&#x274C;',
  };

  const sourceLabel: Record<string, string> = {
    claude: 'Claude',
    gemini: 'Gemini',
    openclaw: 'OpenClaw',
  };

  const pillClass: Record<string, string> = {
    PROTECTED: 'pill pill-green',
    PARTIAL: 'pill pill-yellow',
    NOT_PROTECTED: 'pill pill-red',
  };

  const auditRows = results
    .sort((a, b) => {
      const order: Record<string, number> = { PROTECTED: 0, PARTIAL: 1, NOT_PROTECTED: 2 };
      return (order[a.status] ?? 2) - (order[b.status] ?? 2);
    })
    .map((r) => `
      <tr>
        <td style="text-align:center;font-size:14px">${statusIcon[r.status]}</td>
        <td><span class="code-tag">${escapeHTML(r.code)}</span></td>
        <td class="cat">${escapeHTML(r.title)}</td>
        <td><span class="${pillClass[r.status]}">${r.status.replace(/_/g, ' ')}</span></td>
        <td class="det">${escapeHTML(r.summary)}</td>
        <td class="det">${r.recommendation ? escapeHTML(r.recommendation) : ''}</td>
      </tr>`).join('');

  const toolRows = allCalls.map((tc) => {
    const session = sessionMap.get(tc.sessionId);
    const argFull = escapeHTML(JSON.stringify(tc.arguments, null, 2));
    const hasArgs = argFull !== '{}';
    const resStr = escapeHTML((tc.result || '').slice(0, 500));
    const src = tc.source;
    const srcClass = 'src-' + src;
    const time = tc.timestamp ? new Date(tc.timestamp).toLocaleTimeString('en-GB', { hour: '2-digit', minute: '2-digit', second: '2-digit' }) : '';
    const dateShort = tc.timestamp ? new Date(tc.timestamp).toLocaleDateString('en-GB', { day: '2-digit', month: '2-digit' }) : '';
    const dateFull = tc.timestamp ? new Date(tc.timestamp).toLocaleDateString('en-GB', { day: 'numeric', month: 'long', year: 'numeric' }) : '';

    return `
      <tr class="log-row ${tc.isError ? 'err-row' : ''}" data-source="${src}" data-date="${dateFull}">
        <td class="ts"><span class="d">${dateShort}</span> ${time}</td>
        <td><span class="src-tag ${srcClass}">${sourceLabel[src] || src}</span></td>
        <td class="tool">${escapeHTML(tc.toolName)}${tc.isError ? '<span class="err-tag">ERR</span>' : ''}</td>
        <td class="args">${hasArgs ? `<div class="acc"><span class="acc-toggle">args</span><div class="acc-body"><div><pre>${argFull}</pre></div></div></div>` : '<span style="color:#2a2a2e">&mdash;</span>'}</td>
        <td>${resStr ? `<div class="acc"><span class="acc-toggle">${tc.isError ? '<span style="color:#f87171">error</span>' : 'result'}</span><div class="acc-body"><div><pre>${resStr}</pre></div></div></div>` : '<span style="color:#2a2a2e">&mdash;</span>'}</td>
        <td class="meta">${escapeHTML(tc.id.slice(0, 8))}<br>${escapeHTML(session?.model || '-')}</td>
      </tr>`;
  }).join('');

  const scoreColor = intScore >= 7 ? '#22c55e' : intScore >= 4 ? '#eab308' : '#ef4444';

  const logoHtml = `<img src="https://cdn.solongate.com/icon-256x256.png" alt="SolonGate" width="36" height="36" style="border-radius:8px">`;

  const html = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<link rel="icon" type="image/png" href="https://cdn.solongate.com/icon-32x32.png" sizes="32x32">
<link rel="icon" type="image/png" href="https://cdn.solongate.com/icon-16x16.png" sizes="16x16">
<link rel="apple-touch-icon" href="https://cdn.solongate.com/icon-192x192.png">
<title>SolonGate Audit Report</title>
<style>
  :root { --bg: #0c0c0e; --surface: #161618; --surface2: #1e1e21; --border: #2a2a2e; --text: #e8e8ec; --text2: #8b8b96; --accent: #7c8aff; }
  * { box-sizing: border-box; margin: 0; padding: 0; }

  /* Custom scrollbar — thin, dark, auto-hide */
  *::-webkit-scrollbar { width: 5px; height: 5px; }
  *::-webkit-scrollbar-track { background: transparent; }
  *::-webkit-scrollbar-thumb { background: transparent; border-radius: 4px; transition: background 0.3s; }
  *:hover::-webkit-scrollbar-thumb { background: #333; }
  *::-webkit-scrollbar-thumb:hover { background: #555; }
  *::-webkit-scrollbar-button { display: none; width: 0; height: 0; }
  * { scrollbar-width: thin; scrollbar-color: transparent transparent; }
  *:hover { scrollbar-color: #333 transparent; }
  body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; background: var(--bg); color: var(--text); line-height: 1.6; -webkit-font-smoothing: antialiased; }
  .wrap { max-width: 1360px; margin: 0 auto; padding: 48px 40px 80px; }

  /* Header */
  .hdr { display: flex; align-items: center; gap: 14px; margin-bottom: 40px; }
  .hdr svg { flex-shrink: 0; }
  .hdr-text h1 { font-size: 20px; font-weight: 600; letter-spacing: -0.3px; color: #fff; }
  .hdr-text p { font-size: 12px; color: var(--text2); margin-top: 1px; }

  /* Grid */
  .grid4 { display: grid; grid-template-columns: repeat(4, 1fr); gap: 12px; margin-bottom: 28px; }
  @media (max-width: 800px) { .grid4 { grid-template-columns: repeat(2, 1fr); } }
  .card { background: var(--surface); border: 1px solid var(--border); border-radius: 10px; padding: 18px 20px; }
  .card-label { font-size: 10px; color: var(--text2); text-transform: uppercase; letter-spacing: 1.2px; font-weight: 500; }
  .card-val { font-size: 26px; font-weight: 700; margin-top: 4px; color: #fff; }
  .card-sub { font-size: 11px; color: var(--text2); margin-top: 2px; }

  /* Score */
  .score-bar { background: var(--surface); border: 1px solid var(--border); border-radius: 10px; padding: 24px 28px; margin-bottom: 28px; display: flex; align-items: center; gap: 24px; }
  .ring { width: 80px; height: 80px; position: relative; flex-shrink: 0; }
  .ring svg { width: 100%; height: 100%; transform: rotate(-90deg); }
  .ring circle { fill: none; stroke-width: 6; }
  .ring .track { stroke: var(--surface2); }
  .ring .fill { stroke: ${scoreColor}; stroke-linecap: round; stroke-dasharray: 0 251; }
  .ring .num { position: absolute; inset: 0; display: flex; align-items: center; justify-content: center; font-size: 22px; font-weight: 700; color: ${scoreColor}; }
  .score-txt h3 { font-size: 15px; font-weight: 600; color: #fff; }
  .score-txt p { font-size: 13px; color: var(--text2); margin-top: 2px; }
  .score-txt a { color: ${scoreColor}; text-decoration: none; font-weight: 500; }

  /* Section */
  .sec { margin-bottom: 28px; }
  .sec-hdr { font-size: 13px; font-weight: 600; color: var(--text2); text-transform: uppercase; letter-spacing: 0.8px; margin-bottom: 12px; display: flex; align-items: center; gap: 8px; }
  .sec-count { background: var(--surface2); font-size: 10px; padding: 1px 7px; border-radius: 8px; font-weight: 600; color: var(--text2); }

  /* Table */
  table { width: 100%; border-collapse: collapse; background: var(--surface); border: 1px solid var(--border); border-radius: 10px; overflow: hidden; }
  th { text-align: left; padding: 10px 14px; background: var(--surface2); font-size: 10px; text-transform: uppercase; letter-spacing: 0.8px; color: var(--text2); font-weight: 600; }
  td { padding: 9px 14px; border-top: 1px solid var(--border); font-size: 12px; vertical-align: top; }
  tbody tr { transition: background 0.15s; }
  tbody tr:hover { background: rgba(124,138,255,0.04); }
  .err-row { background: rgba(239,68,68,0.05); }
  .err-row:hover { background: rgba(239,68,68,0.08); }

  /* Badges */
  .pill { display: inline-block; padding: 2px 9px; border-radius: 4px; font-size: 10px; font-weight: 600; text-transform: uppercase; letter-spacing: 0.3px; }
  .pill-green { background: rgba(34,197,94,0.12); color: #4ade80; }
  .pill-yellow { background: rgba(234,179,8,0.12); color: #facc15; }
  .pill-red { background: rgba(239,68,68,0.12); color: #f87171; }
  .code-tag { color: var(--accent); font-weight: 600; font-size: 11px; }
  .src-tag { display: inline-block; padding: 1px 7px; border-radius: 3px; font-size: 10px; font-weight: 600; }
  .src-claude { background: rgba(192,132,252,0.12); color: #c084fc; }
  .src-gemini { background: rgba(96,165,250,0.12); color: #60a5fa; }
  .src-openclaw { background: rgba(74,222,128,0.12); color: #4ade80; }
  .err-tag { background: rgba(239,68,68,0.15); color: #f87171; padding: 0 5px; border-radius: 3px; font-size: 9px; font-weight: 700; margin-left: 4px; }
  .cat { font-weight: 500; }
  .det { font-size: 11px; color: var(--text2); max-width: 280px; line-height: 1.4; }

  /* Mono cells */
  .ts { white-space: nowrap; font-family: 'SF Mono', 'Cascadia Code', 'Consolas', monospace; font-size: 11px; color: var(--text2); }
  .ts .d { color: #3f3f46; }
  .tool { font-family: 'SF Mono', 'Cascadia Code', 'Consolas', monospace; font-size: 11px; font-weight: 500; white-space: nowrap; }
  .args { font-family: 'SF Mono', 'Cascadia Code', 'Consolas', monospace; font-size: 11px; max-width: 380px; word-break: break-all; line-height: 1.4; }
  .meta { font-family: 'SF Mono', 'Cascadia Code', 'Consolas', monospace; font-size: 10px; color: var(--text2); white-space: nowrap; }

  /* Accordion — animated with CSS grid trick */
  .acc { margin-top: 4px; }
  .acc-toggle { cursor: pointer; color: var(--accent); font-size: 10px; font-weight: 500; user-select: none; display: inline-flex; align-items: center; gap: 3px; opacity: 0.7; transition: opacity 0.15s; }
  .acc-toggle:hover { opacity: 1; }
  .acc-toggle::before { content: '\\25B8'; font-size: 8px; transition: transform 0.25s cubic-bezier(0.4, 0, 0.2, 1); display: inline-block; }
  .acc-body { display: grid; grid-template-rows: 0fr; transition: grid-template-rows 0.3s cubic-bezier(0.4, 0, 0.2, 1), opacity 0.25s ease; opacity: 0; }
  .acc-body > div { overflow: hidden; }
  .acc.open .acc-toggle::before { transform: rotate(90deg); }
  .acc.open .acc-body { grid-template-rows: 1fr; opacity: 1; }
  .acc pre { background: var(--bg); padding: 10px 12px; border-radius: 6px; margin-top: 6px; font-size: 10px; max-height: 220px; overflow: auto; white-space: pre-wrap; word-break: break-all; border: 1px solid var(--border); color: var(--text2); line-height: 1.5; }

  /* Filter */
  .filters { display: flex; gap: 8px; margin-bottom: 12px; flex-wrap: wrap; }
  .filters input, .filters select { background: var(--surface); border: 1px solid var(--border); color: var(--text); padding: 7px 12px; border-radius: 6px; font-size: 12px; outline: none; transition: border-color 0.2s; }
  .filters input:focus, .filters select:focus { border-color: var(--accent); }
  .filters input { flex: 1; min-width: 220px; }

  /* Pagination */
  .pager { display: flex; align-items: center; justify-content: center; gap: 4px; margin-top: 16px; flex-wrap: wrap; }
  .pager button { background: var(--surface); border: 1px solid var(--border); color: var(--text2); padding: 6px 12px; border-radius: 6px; font-size: 12px; cursor: pointer; transition: background 0.15s, color 0.15s, border-color 0.15s; }
  .pager button:hover { background: var(--surface2); color: var(--text); }
  .pager button.active { background: var(--accent); color: #000; border-color: var(--accent); font-weight: 600; }
  .pager button:disabled { opacity: 0.3; cursor: default; }
  .pager .pager-info { font-size: 11px; color: var(--text2); margin: 0 8px; }
  .date-sep { background: var(--surface2); }
  .date-sep td { padding: 6px 14px; font-size: 11px; font-weight: 600; color: var(--text2); letter-spacing: 0.5px; border: none; }

  /* Skeleton loading */
  .skel-row td { padding: 12px 14px; }
  .skel-bar { height: 12px; border-radius: 4px; background: var(--surface2); position: relative; overflow: hidden; }
  .skel-bar::after { content: ''; position: absolute; inset: 0; background: linear-gradient(90deg, transparent, rgba(255,255,255,0.03), transparent); animation: shimmer 1.8s infinite; }
  @keyframes shimmer { 0% { transform: translateX(-100%); } 100% { transform: translateX(100%); } }
  .skel-w1 { width: 72px; }
  .skel-w2 { width: 52px; }
  .skel-w3 { width: 88px; }
  .skel-w4 { width: 120px; }
  .skel-w5 { width: 90px; }
  .skel-w6 { width: 60px; }
  #lt tbody.loading .log-row { display: none; }
  #lt tbody.loading .date-sep { display: none; }

  /* Footer */
  .ftr { text-align: center; margin-top: 56px; padding-top: 24px; border-top: 1px solid var(--border); }
  .ftr a { color: var(--text2); text-decoration: none; font-size: 12px; font-weight: 500; transition: color 0.15s; }
  .ftr a:hover { color: #fff; }
  .ftr p { color: #3f3f46; font-size: 11px; margin-top: 4px; }

  @media print {
    body { background: #fff; color: #111; }
    .wrap { padding: 16px; }
    .card, .score-bar, table { background: #fff; border-color: #e5e5e5; }
    th { background: #f5f5f5; color: #333; }
    td { border-color: #eee; }
    .acc pre { background: #f8f8f8; border-color: #e5e5e5; }
    tbody tr:hover { background: transparent; }
    .err-row { background: #fef2f2; }
    .filters { display: none; }
    @page { size: A4 landscape; margin: 8mm; }
  }
</style>
</head>
<body>
<div class="wrap">

<div class="hdr">
  ${logoHtml}
  <div class="hdr-text">
    <h1>Security Audit</h1>
    <p>OWASP Agentic Top 10 &middot; ${new Date().toLocaleDateString('en-GB', { day: 'numeric', month: 'short', year: 'numeric' })}</p>
  </div>
</div>

<div class="grid4">
  <div class="card"><div class="card-label">AI Tools</div><div class="card-val">${data.sources.length}</div><div class="card-sub">${data.sources.join(', ') || 'None'}</div></div>
  <div class="card"><div class="card-label">Sessions</div><div class="card-val">${data.sessions.length}</div><div class="card-sub">${data.timeRange ? new Date(data.timeRange.from).toLocaleDateString('en-GB', {day:'numeric',month:'short'}) + ' &ndash; ' + new Date(data.timeRange.to).toLocaleDateString('en-GB', {day:'numeric',month:'short',year:'numeric'}) : '-'}</div></div>
  <div class="card"><div class="card-label">Tool Calls</div><div class="card-val">${data.totalToolCalls.toLocaleString()}</div><div class="card-sub">${errorCount > 0 ? errorCount + ' error' + (errorCount > 1 ? 's' : '') : 'No errors'}</div></div>
  <div class="card"><div class="card-label">Critical Issues</div><div class="card-val" style="color:${fixCount > 0 ? '#f87171' : '#4ade80'}">${fixCount}</div><div class="card-sub">${fixCount > 0 ? 'need attention' : 'none'}</div></div>
</div>

<div class="score-bar">
  <div class="ring">
    <svg viewBox="0 0 100 100"><circle class="track" cx="50" cy="50" r="40"/><circle class="fill" cx="50" cy="50" r="40"/></svg>
    <div class="num">${intScore}</div>
  </div>
  <div class="score-txt">
    <h3>${intScore}/10</h3>
    <p>${intScore >= 7 ? 'Good protection.' : intScore >= 4 ? 'Several categories need attention.' : 'Critical gaps across multiple categories.'}</p>
    ${fixCount > 0 ? `<p style="margin-top:6px"><a href="https://solongate.com">Fix ${fixCount} issue${fixCount > 1 ? 's' : ''} &rarr;</a></p>` : ''}
  </div>
</div>

<div class="sec">
  <div class="sec-hdr">Audit Results <span class="sec-count">${results.length}</span></div>
  <table>
    <thead><tr><th style="width:32px"></th><th>Code</th><th>Category</th><th>Status</th><th>Details</th><th>Recommendation</th></tr></thead>
    <tbody>${auditRows}</tbody>
  </table>
</div>

<div class="sec">
  <div class="sec-hdr">Tool Calls <span class="sec-count">${allCalls.length.toLocaleString()}</span></div>
  <div class="filters">
    <input type="text" id="q" placeholder="Search..." oninput="applyFilters()">
    <select id="sf" onchange="applyFilters()"><option value="">All sources</option><option value="claude">Claude</option><option value="gemini">Gemini</option><option value="openclaw">OpenClaw</option></select>
    <select id="ef" onchange="applyFilters()"><option value="">All</option><option value="e">Errors</option><option value="s">Success</option></select>
    <select id="df" onchange="applyFilters()"><option value="">All dates</option></select>
  </div>
  <table id="lt">
    <thead><tr><th>Time</th><th>Source</th><th>Tool</th><th>Arguments</th><th>Result</th><th>Meta</th></tr></thead>
    <tbody class="loading">
      ${Array.from({length: 12}, () => `<tr class="skel-row"><td><div class="skel-bar skel-w1"></div></td><td><div class="skel-bar skel-w2"></div></td><td><div class="skel-bar skel-w3"></div></td><td><div class="skel-bar skel-w4"></div></td><td><div class="skel-bar skel-w5"></div></td><td><div class="skel-bar skel-w6"></div></td></tr>`).join('')}
      ${toolRows}
    </tbody>
  </table>
  <div class="pager" id="pager"></div>
</div>

<div class="ftr">
  <a href="https://solongate.com">solongate.com</a>
  <p>AI Agent Security</p>
</div>

</div>
<script>
(function(){
  var PER_PAGE = 100;
  var page = 1;
  var allRows = Array.from(document.querySelectorAll('#lt tbody tr.log-row'));
  var filtered = allRows.slice();
  var tbody = document.querySelector('#lt tbody');

  // Populate date dropdown
  var dates = [];
  var seen = {};
  allRows.forEach(function(r){
    var d = r.getAttribute('data-date');
    if(d && !seen[d]){ seen[d]=1; dates.push(d); }
  });
  var df = document.getElementById('df');
  dates.forEach(function(d){
    var o = document.createElement('option');
    o.value = d; o.textContent = d;
    df.appendChild(o);
  });

  // Accordion
  document.addEventListener('click',function(e){
    var t=e.target.closest('.acc-toggle');
    if(t){t.closest('.acc').classList.toggle('open');}
  });

  function applyFilters(){
    var q = document.getElementById('q').value.toLowerCase();
    var s = document.getElementById('sf').value;
    var ef = document.getElementById('ef').value;
    var dv = document.getElementById('df').value;
    filtered = allRows.filter(function(r){
      var txt = r.textContent.toLowerCase();
      var src = r.getAttribute('data-source')||'';
      var dt = r.getAttribute('data-date')||'';
      var err = r.classList.contains('err-row');
      return (!q||txt.indexOf(q)!==-1)&&(!s||src===s)&&(!dv||dt===dv)&&(!ef||(ef==='e'&&err)||(ef==='s'&&!err));
    });
    page = 1;
    render();
  }
  window.applyFilters = applyFilters;

  function render(){
    var total = filtered.length;
    var pages = Math.max(1, Math.ceil(total / PER_PAGE));
    if(page > pages) page = pages;
    var start = (page-1)*PER_PAGE;
    var end = Math.min(start+PER_PAGE, total);
    var slice = filtered.slice(start, end);

    // Clear tbody and insert date-grouped rows
    tbody.innerHTML = '';
    var lastDate = '';
    slice.forEach(function(r){
      var d = r.getAttribute('data-date')||'';
      if(d && d !== lastDate){
        lastDate = d;
        var sep = document.createElement('tr');
        sep.className = 'date-sep';
        sep.innerHTML = '<td colspan="6">' + d + '</td>';
        tbody.appendChild(sep);
      }
      tbody.appendChild(r);
    });

    // Pagination controls
    var pager = document.getElementById('pager');
    var html = '';
    html += '<button '+(page<=1?'disabled':'')+' onclick="pg('+(page-1)+')">&lsaquo;</button>';
    var s = Math.max(1, page-3), e = Math.min(pages, page+3);
    if(s > 1) html += '<button onclick="pg(1)">1</button>';
    if(s > 2) html += '<span class="pager-info">&hellip;</span>';
    for(var i=s;i<=e;i++){
      html += '<button class="'+(i===page?'active':'')+'" onclick="pg('+i+')">'+i+'</button>';
    }
    if(e < pages-1) html += '<span class="pager-info">&hellip;</span>';
    if(e < pages) html += '<button onclick="pg('+pages+')">'+pages+'</button>';
    html += '<button '+(page>=pages?'disabled':'')+' onclick="pg('+(page+1)+')">&rsaquo;</button>';
    html += '<span class="pager-info">' + (start+1) + '&ndash;' + end + ' of ' + total + '</span>';
    pager.innerHTML = html;
  }

  window.pg = function(p){ page=p; render(); window.scrollTo({top:document.getElementById('lt').offsetTop-80,behavior:'smooth'}); };

  // Score ring animation
  requestAnimationFrame(function(){setTimeout(function(){
    var c=document.querySelector('.ring .fill');
    if(c) c.style.strokeDasharray='${Math.round((intScore / 10) * 251)} 251';
  },100)});

  // Remove skeleton, show real rows
  tbody.classList.remove('loading');
  document.querySelectorAll('.skel-row').forEach(function(r){ r.remove(); });
  render();
})();
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
