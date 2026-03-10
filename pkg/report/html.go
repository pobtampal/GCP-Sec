package report

import (
	"fmt"
	"html/template"
	"io"
	"sort"
	"strings"
	"time"

	"github.com/wanaware/GCP-Sec/internal/models"
	"github.com/wanaware/GCP-Sec/internal/utils"
)

const htmlTemplate = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1.0"/>
<title>GCP Security Findings Report</title>
<style>
/* ── Variables ─────────────────────────────────────────────────── */
:root {
  /* Severity colors: muted enough not to dominate, vivid enough to scan */
  --c:    #dc2626; --c-bg: #fef2f2; --c-border: rgba(220,38,38,.18);
  --h:    #b45309; --h-bg: #fffbeb; --h-border: rgba(180,83,9,.18);
  --m:    #92400e; --m-bg: #fefce8; --m-border: rgba(146,64,14,.18);
  --l:    #166534; --l-bg: #f0fdf4; --l-border: rgba(22,101,52,.18);
  /* Chrome */
  --blue:      #2563eb;
  --blue-bg:   #eff6ff;
  --navy:      #0f172a;   /* sidebar, page-header */
  --page-bg:   #f1f5f9;
  --card:      #ffffff;
  --border:    #e2e8f0;
  --border-2:  #f1f5f9;   /* lighter dividers inside cards */
  /* Text */
  --t1: #0f172a;   /* primary   */
  --t2: #475569;   /* secondary */
  --t3: #94a3b8;   /* tertiary  */
}

/* ── Reset ─────────────────────────────────────────────────────── */
*, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }

/* ── Base ──────────────────────────────────────────────────────── */
body {
  font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', system-ui, sans-serif;
  font-size: 14px;
  line-height: 1.65;
  color: var(--t1);
  background: var(--page-bg);
  -webkit-font-smoothing: antialiased;
}

/* ── Layout ────────────────────────────────────────────────────── */
.layout { display: flex; min-height: 100vh; }

/* ── Sidebar ───────────────────────────────────────────────────── */
nav {
  width: 218px;
  flex-shrink: 0;
  background: var(--navy);
  position: sticky;
  top: 0;
  height: 100vh;
  overflow-y: auto;
  scrollbar-width: thin;
  scrollbar-color: #334155 transparent;
}
nav::-webkit-scrollbar { width: 3px; }
nav::-webkit-scrollbar-thumb { background: #334155; border-radius: 2px; }

.nav-brand {
  padding: 18px 16px 15px;
  border-bottom: 1px solid rgba(255,255,255,.07);
}
.nav-brand .title {
  font-size: 13px;
  font-weight: 600;
  color: #f1f5f9;
  letter-spacing: .1px;
}
.nav-brand .sub {
  font-size: 11px;
  color: var(--t3);
  margin-top: 3px;
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
}

nav ul { list-style: none; padding: 6px 0 20px; }

.nav-group {
  padding: 14px 16px 4px;
  font-size: 10px;
  font-weight: 700;
  letter-spacing: 1px;
  text-transform: uppercase;
  color: #475569;
}

nav ul li a {
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 7px 16px;
  font-size: 12.5px;
  color: #94a3b8;
  text-decoration: none;
  border-left: 2px solid transparent;
  transition: color .12s, background .12s;
}
nav ul li a:hover  { color: #cbd5e1; background: rgba(255,255,255,.05); }
nav ul li a.active { color: #fff; background: rgba(37,99,235,.2); border-left-color: var(--blue); }
.nav-dot {
  width: 7px; height: 7px; border-radius: 50%; flex-shrink: 0;
}
.nd-c { background: var(--c); }
.nd-h { background: var(--h); }
.nd-m { background: var(--m); }
.nd-l { background: var(--l); }
.nd-b { background: var(--blue); }

/* ── Main ──────────────────────────────────────────────────────── */
main {
  flex: 1;
  padding: 28px 36px 48px;
  overflow-x: hidden;
}

/* ── Page header ───────────────────────────────────────────────── */
.page-header {
  background: var(--navy);
  color: #fff;
  padding: 24px 28px;
  border-radius: 10px;
  margin-bottom: 28px;
  display: flex;
  justify-content: space-between;
  align-items: center;
  gap: 24px;
}
.page-header h1 {
  font-size: 19px;
  font-weight: 700;
  letter-spacing: -.3px;
  margin-bottom: 7px;
  color: #f8fafc;
}
.page-header .meta { font-size: 12px; color: var(--t3); }
.page-header .meta span { display: block; margin-top: 3px; }

.hdr-total {
  text-align: center;
  flex-shrink: 0;
  background: rgba(255,255,255,.06);
  border: 1px solid rgba(255,255,255,.1);
  border-radius: 8px;
  padding: 14px 22px;
}
.hdr-total .n { font-size: 34px; font-weight: 700; line-height: 1; color: #fff; }
.hdr-total .l { font-size: 11px; color: var(--t3); margin-top: 4px; letter-spacing: .3px; }

/* ── Sections ──────────────────────────────────────────────────── */
section { margin-bottom: 32px; scroll-margin-top: 20px; }

.sec-head {
  display: flex;
  align-items: baseline;
  gap: 10px;
  margin-bottom: 14px;
  padding-bottom: 9px;
  border-bottom: 1px solid var(--border);
}
.sec-head h2 { font-size: 14.5px; font-weight: 700; color: var(--t1); letter-spacing: -.1px; }
.sec-head .sub-count { font-size: 12px; color: var(--t2); font-weight: 400; }

/* ── Cards ─────────────────────────────────────────────────────── */
.card {
  background: var(--card);
  border: 1px solid var(--border);
  border-radius: 8px;
  padding: 20px 22px;
}

/* ── Stat grid ─────────────────────────────────────────────────── */
.stat-row {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(130px, 1fr));
  gap: 10px;
  margin-bottom: 14px;
}
.stat-card {
  background: var(--card);
  border: 1px solid var(--border);
  border-top: 3px solid var(--border);
  border-radius: 8px;
  padding: 14px 16px;
}
.stat-card.total    { border-top-color: var(--blue); }
.stat-card.critical { border-top-color: var(--c);    }
.stat-card.high     { border-top-color: var(--h);    }
.stat-card.medium   { border-top-color: var(--m);    }
.stat-card.low      { border-top-color: var(--l);    }

.sn { font-size: 26px; font-weight: 700; line-height: 1.1; margin-bottom: 3px; }
.stat-card.total    .sn { color: var(--blue); }
.stat-card.critical .sn { color: var(--c);    }
.stat-card.high     .sn { color: var(--h);    }
.stat-card.medium   .sn { color: var(--m);    }
.stat-card.low      .sn { color: var(--l);    }
.sl { font-size: 12px; color: var(--t2); }
.sp { font-size: 11px; color: var(--t3); margin-top: 1px; }

/* ── Distribution bar ──────────────────────────────────────────── */
.dist-label { font-size: 11.5px; font-weight: 600; color: var(--t2); margin-bottom: 7px; }
.dist-bar {
  height: 7px;
  border-radius: 4px;
  background: var(--border);
  overflow: hidden;
  display: flex;
}
.dist-bar .seg        { height: 100%; }
.seg.critical         { background: var(--c); }
.seg.high             { background: var(--h); }
.seg.medium           { background: var(--m); }
.seg.low              { background: var(--l); }

.dist-legend { display: flex; flex-wrap: wrap; gap: 14px; margin-top: 9px; }
.dist-legend span {
  font-size: 11.5px; color: var(--t2);
  display: flex; align-items: center; gap: 5px;
}
.dist-legend span::before {
  content: ''; width: 8px; height: 8px; border-radius: 2px; display: inline-block;
}
.dl-c::before { background: var(--c); }
.dl-h::before { background: var(--h); }
.dl-m::before { background: var(--m); }
.dl-l::before { background: var(--l); }

/* ── Divider ───────────────────────────────────────────────────── */
.div { border: none; border-top: 1px solid var(--border-2); margin: 18px 0; }

/* ── Risk stats ────────────────────────────────────────────────── */
.rs-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(100px, 1fr));
  gap: 8px;
  margin-top: 12px;
}
.rs-item {
  background: var(--page-bg);
  border: 1px solid var(--border);
  border-radius: 6px;
  padding: 10px 14px;
}
.rs-val { font-size: 18px; font-weight: 700; color: var(--blue); line-height: 1.2; }
.rs-key { font-size: 11px; color: var(--t2); margin-top: 3px; }

/* ── Sub-label ─────────────────────────────────────────────────── */
.sub-lbl { font-size: 12.5px; font-weight: 600; color: var(--t1); }

/* ── Top categories ────────────────────────────────────────────── */
.top-cat-list { list-style: none; margin-top: 10px; }
.top-cat-list li {
  display: flex;
  align-items: center;
  gap: 10px;
  padding: 6px 0;
  border-bottom: 1px solid var(--border-2);
}
.top-cat-list li:last-child { border-bottom: none; }
.tc-num {
  width: 19px; height: 19px; border-radius: 50%;
  background: var(--blue-bg); color: var(--blue);
  font-size: 10px; font-weight: 700;
  display: flex; align-items: center; justify-content: center; flex-shrink: 0;
}
.tc-name { flex: 1; font-family: 'Menlo', 'Consolas', monospace; font-size: 11.5px; color: var(--t1); }
.tc-cnt  { font-size: 12px; font-weight: 600; color: var(--t2); white-space: nowrap; }

/* ── Tables ────────────────────────────────────────────────────── */
.tbl-outer { overflow-x: auto; border: 1px solid var(--border); border-radius: 8px; }

table { width: 100%; border-collapse: collapse; background: var(--card); font-size: 13px; }

thead th {
  background: #f8fafc;
  color: var(--t2);
  font-size: 11px;
  font-weight: 700;
  padding: 9px 14px;
  text-align: left;
  white-space: nowrap;
  border-bottom: 1px solid var(--border);
  text-transform: uppercase;
  letter-spacing: .5px;
}

tbody tr { transition: background .1s; }
tbody tr:hover { background: #f8fafc; }
tbody td {
  padding: 8px 14px;
  border-bottom: 1px solid var(--border-2);
  color: var(--t1);
  vertical-align: middle;
}
tbody tr:last-child td { border-bottom: none; }

.tr  { text-align: right; }
.mono { font-family: 'Menlo', 'Consolas', monospace; font-size: 12px; }
.dim  { color: var(--t2); }

/* ── Badges ────────────────────────────────────────────────────── */
.badge {
  display: inline-flex;
  align-items: center;
  padding: 2px 8px;
  border-radius: 4px;
  font-size: 11px;
  font-weight: 700;
  letter-spacing: .3px;
  white-space: nowrap;
  border: 1px solid transparent;
}
.b-CRITICAL { background: var(--c-bg); color: var(--c); border-color: var(--c-border); }
.b-HIGH     { background: var(--h-bg); color: var(--h); border-color: var(--h-border); }
.b-MEDIUM   { background: var(--m-bg); color: var(--m); border-color: var(--m-border); }
.b-LOW      { background: var(--l-bg); color: var(--l); border-color: var(--l-border); }

/* ── Score chips (monospace, outlined) ─────────────────────────── */
.score {
  display: inline-block;
  font-family: 'Menlo', 'Consolas', monospace;
  font-size: 12px;
  font-weight: 700;
  padding: 1px 7px;
  border-radius: 4px;
  border: 1px solid transparent;
}
.s-CRITICAL { background: var(--c-bg); color: var(--c); border-color: var(--c-border); }
.s-HIGH     { background: var(--h-bg); color: var(--h); border-color: var(--h-border); }
.s-MEDIUM   { background: var(--m-bg); color: var(--m); border-color: var(--m-border); }
.s-LOW      { background: var(--l-bg); color: var(--l); border-color: var(--l-border); }

/* ── Search input ──────────────────────────────────────────────── */
.search-wrap { margin-bottom: 10px; }
.srch {
  display: block;
  width: 100%;
  max-width: 320px;
  padding: 7px 12px;
  border: 1px solid var(--border);
  border-radius: 6px;
  font-size: 13px;
  color: var(--t1);
  background: var(--card);
  outline: none;
  transition: border-color .15s, box-shadow .15s;
}
.srch:focus { border-color: var(--blue); box-shadow: 0 0 0 3px rgba(37,99,235,.1); }
.srch::placeholder { color: var(--t3); }

/* ── Threshold pills ───────────────────────────────────────────── */
.thr-row { display: flex; flex-wrap: wrap; gap: 7px; margin-top: 14px; }
.thr {
  font-size: 12px; font-weight: 600;
  padding: 4px 11px;
  border-radius: 5px;
  border: 1px solid transparent;
}
.thr.c { background: var(--c-bg); color: var(--c); border-color: var(--c-border); }
.thr.h { background: var(--h-bg); color: var(--h); border-color: var(--h-border); }
.thr.m { background: var(--m-bg); color: var(--m); border-color: var(--m-border); }
.thr.l { background: var(--l-bg); color: var(--l); border-color: var(--l-border); }

/* ── Compliance grid ───────────────────────────────────────────── */
.comp-grid {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(252px, 1fr));
  gap: 10px;
}
.comp-card {
  background: var(--card);
  border: 1px solid var(--border);
  border-top: 3px solid var(--blue);
  border-radius: 8px;
  padding: 15px 17px;
}
.comp-hdr {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 10px;
}
.comp-fw { font-size: 13px; font-weight: 700; color: var(--t1); }
.comp-badge {
  font-size: 11px;
  background: var(--blue-bg);
  color: var(--blue);
  padding: 1px 7px;
  border-radius: 10px;
  font-weight: 600;
}
.comp-list { list-style: none; }
.comp-list li {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: 4px 0;
  border-bottom: 1px solid var(--border-2);
  font-size: 12px;
}
.comp-list li:last-child { border-bottom: none; }
.comp-ctrl { font-family: 'Menlo', 'Consolas', monospace; font-size: 11.5px; color: var(--t1); }
.comp-n    { font-weight: 600; color: var(--t2); }

/* ── Remediation accordion ─────────────────────────────────────── */
.rem-item {
  border: 1px solid var(--border);
  border-radius: 8px;
  margin-bottom: 6px;
  overflow: hidden;
  background: var(--card);
}
.rem-hdr {
  display: flex;
  align-items: center;
  gap: 11px;
  padding: 11px 15px;
  cursor: pointer;
  user-select: none;
  border-left: 3px solid var(--border);
  transition: background .1s;
}
.rem-hdr:hover { background: var(--page-bg); }
.rem-hdr.critical { border-left-color: var(--c); }
.rem-hdr.high     { border-left-color: var(--h); }
.rem-hdr.medium   { border-left-color: var(--m); }
.rem-hdr.low      { border-left-color: var(--l); }

.rem-hdr .ri  { flex: 1; min-width: 0; }
.rem-hdr .rt  { font-size: 13px; font-weight: 600; color: var(--t1); overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.rem-hdr .rm  { font-size: 11.5px; color: var(--t2); margin-top: 1px; }
.rem-hdr .rc  { font-size: 10px; color: var(--t3); flex-shrink: 0; transition: transform .2s; }
.rem-hdr.open .rc { transform: rotate(180deg); }

.rem-body {
  display: none;
  padding: 16px 17px;
  border-top: 1px solid var(--border-2);
}
.rem-body.open { display: block; }

.rem-lbl {
  font-size: 10.5px;
  font-weight: 700;
  text-transform: uppercase;
  letter-spacing: .6px;
  color: var(--t3);
  margin: 14px 0 6px;
}
.rem-lbl:first-child { margin-top: 0; }

.rem-rationale {
  background: var(--blue-bg);
  border-left: 3px solid var(--blue);
  padding: 8px 12px;
  border-radius: 0 5px 5px 0;
  font-size: 12px;
  color: #1e40af;
  margin-bottom: 12px;
  line-height: 1.55;
}

.rem-tags { display: flex; flex-wrap: wrap; gap: 5px; margin-bottom: 12px; }
.rem-tag {
  background: var(--page-bg);
  border: 1px solid var(--border);
  border-radius: 20px;
  padding: 2px 9px;
  font-size: 11.5px;
  color: var(--t2);
}
.rem-tag strong { color: var(--t1); margin-right: 2px; }

.rem-body p    { font-size: 13px; line-height: 1.65; margin-bottom: 8px; color: var(--t1); }
.rem-body ul   { padding-left: 18px; }
.rem-body ul li { font-size: 13px; line-height: 1.65; margin-bottom: 4px; color: var(--t1); }
.rem-body a    { color: var(--blue); text-decoration: none; }
.rem-body a:hover { text-decoration: underline; }

.rem-effort { display: flex; flex-wrap: wrap; gap: 7px; margin-top: 10px; }
.rem-etag {
  background: var(--page-bg);
  border: 1px solid var(--border);
  border-radius: 5px;
  padding: 3px 9px;
  font-size: 11.5px;
  color: var(--t2);
}
.rem-etag strong { color: var(--t1); margin-right: 3px; }

.rem-code {
  background: #0f172a;
  color: #e2e8f0;
  padding: 13px 15px;
  border-radius: 6px;
  font-family: 'Menlo', 'Consolas', monospace;
  font-size: 12px;
  line-height: 1.55;
  overflow-x: auto;
  white-space: pre-wrap;
  word-break: break-all;
  margin-top: 6px;
}

/* ── Footer ────────────────────────────────────────────────────── */
.footer {
  text-align: center;
  font-size: 12px;
  color: var(--t3);
  padding: 22px 0 6px;
  border-top: 1px solid var(--border);
  margin-top: 40px;
}
.footer a { color: var(--blue); text-decoration: none; }

/* ── Print ─────────────────────────────────────────────────────── */
@media print {
  nav { display: none !important; }
  main { padding: 0; }
  .page-header { background: #000 !important; print-color-adjust: exact; -webkit-print-color-adjust: exact; }
  .rem-body { display: block !important; }
  section { break-inside: avoid; }
}

/* ── Responsive ────────────────────────────────────────────────── */
@media (max-width: 860px) {
  nav { display: none; }
  main { padding: 16px; }
  .page-header { flex-direction: column; align-items: flex-start; gap: 14px; }
  .stat-row { grid-template-columns: repeat(2, 1fr); }
}
</style>
</head>
<body>
<div class="layout">

<!-- ── Sidebar ──────────────────────────────────────────────────── -->
<nav>
  <div class="nav-brand">
    <div class="title">GCP Security Report</div>
    <div class="sub">{{ .InputFile }}</div>
  </div>
  <ul>
    <li class="nav-group">Overview</li>
    <li><a href="#summary"><span class="nav-dot nd-b"></span>Executive Summary</a></li>
    <li><a href="#priority"><span class="nav-dot nd-b"></span>Priority Breakdown</a></li>
    <li><a href="#methodology"><span class="nav-dot nd-b"></span>Risk Methodology</a></li>
    <li class="nav-group">Findings</li>
    <li><a href="#critical-findings"><span class="nav-dot nd-c"></span>Critical</a></li>
    <li><a href="#high-findings"><span class="nav-dot nd-h"></span>High</a></li>
    <li><a href="#medium-findings"><span class="nav-dot nd-m"></span>Medium</a></li>
    <li><a href="#low-findings"><span class="nav-dot nd-l"></span>Low</a></li>
    <li class="nav-group">Analysis</li>
    {{ if .ComplianceSummary }}<li><a href="#compliance"><span class="nav-dot nd-b"></span>Compliance</a></li>{{ end }}
    <li><a href="#categories"><span class="nav-dot nd-b"></span>Categories</a></li>
    <li><a href="#projects"><span class="nav-dot nd-b"></span>Projects</a></li>
    <li class="nav-group">Actions</li>
    <li><a href="#remediation"><span class="nav-dot nd-c"></span>Remediation</a></li>
  </ul>
</nav>

<!-- ── Main content ─────────────────────────────────────────────── -->
<main>

  <!-- Page header -->
  <div class="page-header">
    <div>
      <h1>GCP Security Findings Analysis Report</h1>
      <div class="meta">
        <span>Generated: {{ .GeneratedAt.UTC.Format "2006-01-02 15:04:05 UTC" }}</span>
        <span>Source: {{ .InputFile }}</span>
      </div>
    </div>
    <div class="hdr-total">
      <div class="n">{{ .Stats.Total }}</div>
      <div class="l">Active Findings</div>
    </div>
  </div>

  <!-- ── Executive Summary ──────────────────────────────────────── -->
  <section id="summary">
    <div class="sec-head"><h2>Executive Summary</h2></div>

    <div class="stat-row">
      <div class="stat-card total">
        <div class="sn">{{ .Stats.Total }}</div>
        <div class="sl">Total Findings</div>
      </div>
      <div class="stat-card critical">
        <div class="sn">{{ .Stats.Critical }}</div>
        <div class="sl">Critical</div>
        <div class="sp">{{ pct .Stats.Critical .Stats.Total }}%</div>
      </div>
      <div class="stat-card high">
        <div class="sn">{{ .Stats.High }}</div>
        <div class="sl">High</div>
        <div class="sp">{{ pct .Stats.High .Stats.Total }}%</div>
      </div>
      <div class="stat-card medium">
        <div class="sn">{{ .Stats.Medium }}</div>
        <div class="sl">Medium</div>
        <div class="sp">{{ pct .Stats.Medium .Stats.Total }}%</div>
      </div>
      <div class="stat-card low">
        <div class="sn">{{ .Stats.Low }}</div>
        <div class="sl">Low</div>
        <div class="sp">{{ pct .Stats.Low .Stats.Total }}%</div>
      </div>
    </div>

    <div class="card">
      <div class="dist-label">Findings Distribution</div>
      <div class="dist-bar">
        <div class="seg critical" style="width:{{ pct .Stats.Critical .Stats.Total }}%"></div>
        <div class="seg high"     style="width:{{ pct .Stats.High     .Stats.Total }}%"></div>
        <div class="seg medium"   style="width:{{ pct .Stats.Medium   .Stats.Total }}%"></div>
        <div class="seg low"      style="width:{{ pct .Stats.Low      .Stats.Total }}%"></div>
      </div>
      <div class="dist-legend">
        <span class="dl-c">Critical &nbsp;{{ pct .Stats.Critical .Stats.Total }}%</span>
        <span class="dl-h">High &nbsp;{{ pct .Stats.High .Stats.Total }}%</span>
        <span class="dl-m">Medium &nbsp;{{ pct .Stats.Medium .Stats.Total }}%</span>
        <span class="dl-l">Low &nbsp;{{ pct .Stats.Low .Stats.Total }}%</span>
      </div>

      <div class="div"></div>
      <div class="sub-lbl">Risk Score Statistics</div>
      <div class="rs-grid">
        <div class="rs-item"><div class="rs-val">{{ printf "%.2f" .Stats.RiskStats.Mean }}</div><div class="rs-key">Mean</div></div>
        <div class="rs-item"><div class="rs-val">{{ printf "%.2f" .Stats.RiskStats.Median }}</div><div class="rs-key">Median</div></div>
        <div class="rs-item"><div class="rs-val">{{ printf "%.0f" .Stats.RiskStats.Min }}&ndash;{{ printf "%.0f" .Stats.RiskStats.Max }}</div><div class="rs-key">Range</div></div>
        <div class="rs-item"><div class="rs-val">{{ printf "%.2f" .Stats.RiskStats.StdDev }}</div><div class="rs-key">Std Dev</div></div>
      </div>

      {{ if .Stats.TopCategories }}
      <div class="div"></div>
      <div class="sub-lbl">Top Risk Categories</div>
      <ul class="top-cat-list">
        {{ range $i, $c := topN .Stats.TopCategories 10 }}
        <li>
          <span class="tc-num">{{ inc $i }}</span>
          <span class="tc-name">{{ $c.Category }}</span>
          <span class="tc-cnt">{{ $c.Count }}</span>
        </li>
        {{ end }}
      </ul>
      {{ end }}
    </div>
  </section>

  <!-- ── Priority Breakdown ─────────────────────────────────────── -->
  <section id="priority">
    <div class="sec-head"><h2>Priority Breakdown</h2></div>
    <div class="tbl-outer">
      <table>
        <thead>
          <tr>
            <th>Priority</th>
            <th class="tr">Count</th>
            <th class="tr">Percentage</th>
            <th class="tr">Avg Risk Score</th>
            <th>Remediation SLA</th>
          </tr>
        </thead>
        <tbody>
          <tr>
            <td><span class="badge b-CRITICAL">CRITICAL</span></td>
            <td class="tr">{{ .Stats.Critical }}</td>
            <td class="tr dim">{{ pct .Stats.Critical .Stats.Total }}%</td>
            <td class="tr"><span class="score s-CRITICAL">{{ avgScore .Findings "CRITICAL" }}</span></td>
            <td>24&ndash;48 hours</td>
          </tr>
          <tr>
            <td><span class="badge b-HIGH">HIGH</span></td>
            <td class="tr">{{ .Stats.High }}</td>
            <td class="tr dim">{{ pct .Stats.High .Stats.Total }}%</td>
            <td class="tr"><span class="score s-HIGH">{{ avgScore .Findings "HIGH" }}</span></td>
            <td>1 week</td>
          </tr>
          <tr>
            <td><span class="badge b-MEDIUM">MEDIUM</span></td>
            <td class="tr">{{ .Stats.Medium }}</td>
            <td class="tr dim">{{ pct .Stats.Medium .Stats.Total }}%</td>
            <td class="tr"><span class="score s-MEDIUM">{{ avgScore .Findings "MEDIUM" }}</span></td>
            <td>30 days</td>
          </tr>
          <tr>
            <td><span class="badge b-LOW">LOW</span></td>
            <td class="tr">{{ .Stats.Low }}</td>
            <td class="tr dim">{{ pct .Stats.Low .Stats.Total }}%</td>
            <td class="tr"><span class="score s-LOW">{{ avgScore .Findings "LOW" }}</span></td>
            <td>90 days</td>
          </tr>
        </tbody>
      </table>
    </div>
  </section>

  <!-- ── Risk Methodology ───────────────────────────────────────── -->
  <section id="methodology">
    <div class="sec-head"><h2>Risk Scoring Methodology</h2></div>
    <div class="card">
      <p style="font-size:13px;color:var(--t2);margin-bottom:14px">
        Findings are scored on a 0&ndash;100 scale using weighted components:
      </p>
      <div class="tbl-outer">
        <table>
          <thead>
            <tr><th>Component</th><th class="tr">Max Points</th><th>Description</th></tr>
          </thead>
          <tbody>
            <tr><td>Base Severity</td>  <td class="tr mono">40</td><td>CRITICAL=40, HIGH=30, MEDIUM=20, LOW=10</td></tr>
            <tr><td>CVSS Score</td>     <td class="tr mono">30</td><td>CVSS v3 base score &times; 3</td></tr>
            <tr><td>Exploitability</td> <td class="tr mono">20</td><td>In-the-wild (+10), Zero-day (+8), Activity (+2&ndash;6)</td></tr>
            <tr><td>Finding Class</td>  <td class="tr mono">10</td><td>THREAT=10, VULN=7, MISCONFIG=5, OBSERVATION=2</td></tr>
            <tr><td>Resource Exposure</td><td class="tr mono">10</td><td>Public IP (+5), Internet-facing (+3), Critical (+2)</td></tr>
            <tr><td>Compliance Impact</td><td class="tr mono">10</td><td>Has frameworks (+5), Details (+3), Audit (+2)</td></tr>
            <tr><td>Category Weight</td><td class="tr mono">&times;0.8&ndash;1.2</td><td>High-risk categories get a 1.2&times; multiplier</td></tr>
          </tbody>
        </table>
      </div>
      <div class="thr-row">
        <span class="thr c">CRITICAL &ge; 75</span>
        <span class="thr h">HIGH 55&ndash;74</span>
        <span class="thr m">MEDIUM 35&ndash;54</span>
        <span class="thr l">LOW &lt; 35</span>
      </div>
    </div>
  </section>

  <!-- ── Top Findings by Priority ──────────────────────────────── -->
  {{ range $priority := priorityOrder }}
  {{ $pFindings := filterPriority $.Findings $priority }}
  {{ if gt (len $pFindings) 0 }}
  <section id="{{ lower $priority }}-findings">
    <div class="sec-head">
      <h2>{{ $priority }} Priority Findings</h2>
      <span class="sub-count">
        {{ len $pFindings }} total{{ if gt (len $pFindings) 20 }}&nbsp;&mdash;&nbsp;top 20 shown{{ end }}
      </span>
    </div>
    <div class="search-wrap">
      <input class="srch" type="text"
        placeholder="Filter {{ $priority }} findings&hellip;"
        onkeyup="filterTable(this,'tbl-{{ lower $priority }}')">
    </div>
    <div class="tbl-outer">
      <table id="tbl-{{ lower $priority }}">
        <thead>
          <tr>
            <th style="width:36px">#</th>
            <th>Category</th>
            <th>Resource</th>
            <th class="tr">Score</th>
            <th>CVE</th>
            <th>Project</th>
          </tr>
        </thead>
        <tbody>
          {{ range $i, $f := topFindings $pFindings 20 }}
          <tr>
            <td class="dim">{{ inc $i }}</td>
            <td>{{ $f.Category }}</td>
            <td class="mono" title="{{ $f.ResourceName }}">{{ truncate $f.ResourceDisplayName 45 }}</td>
            <td class="tr"><span class="score s-{{ $f.Priority }}">{{ riskScore $f }}</span></td>
            <td class="dim">{{ cve $f }}</td>
            <td class="dim">{{ $f.ProjectDisplayName }}</td>
          </tr>
          {{ end }}
        </tbody>
      </table>
    </div>
  </section>
  {{ end }}
  {{ end }}

  <!-- ── Compliance ─────────────────────────────────────────────── -->
  {{ if .ComplianceSummary }}
  <section id="compliance">
    <div class="sec-head"><h2>Compliance Framework Violations</h2></div>
    <div class="comp-grid">
      {{ range $fw := sortedFrameworks $.ComplianceSummary }}
      {{ $vs := index $.ComplianceSummary $fw }}
      <div class="comp-card">
        <div class="comp-hdr">
          <span class="comp-fw">{{ $fw }}</span>
          <span class="comp-badge">{{ len $vs }} controls</span>
        </div>
        <ul class="comp-list">
          {{ range topViolations $vs 5 }}
          <li>
            <span class="comp-ctrl">{{ .Framework }} {{ .Control }}</span>
            <span class="comp-n">{{ .Count }}</span>
          </li>
          {{ end }}
        </ul>
      </div>
      {{ end }}
    </div>
  </section>
  {{ end }}

  <!-- ── Category Breakdown ────────────────────────────────────── -->
  <section id="categories">
    <div class="sec-head"><h2>Category Breakdown</h2></div>
    <div class="tbl-outer">
      <table>
        <thead>
          <tr>
            <th>Category</th>
            <th class="tr">Total</th>
            <th class="tr">Critical</th>
            <th class="tr">High</th>
            <th class="tr">Medium</th>
            <th class="tr">Low</th>
            <th class="tr">Avg Score</th>
          </tr>
        </thead>
        <tbody>
          {{ range sortedCategories .CategoryBreakdown }}
          <tr>
            <td class="mono">{{ .Category }}</td>
            <td class="tr">{{ .Count }}</td>
            <td class="tr dim">{{ .Critical }}</td>
            <td class="tr dim">{{ .High }}</td>
            <td class="tr dim">{{ .Medium }}</td>
            <td class="tr dim">{{ .Low }}</td>
            <td class="tr"><span class="score s-{{ scoreClass .AvgRiskScore }}">{{ printf "%.1f" .AvgRiskScore }}</span></td>
          </tr>
          {{ end }}
        </tbody>
      </table>
    </div>
  </section>

  <!-- ── Project Breakdown ─────────────────────────────────────── -->
  <section id="projects">
    <div class="sec-head"><h2>Project Breakdown</h2></div>
    <div class="tbl-outer">
      <table>
        <thead>
          <tr>
            <th>Project</th>
            <th class="tr">Total</th>
            <th class="tr">Critical</th>
            <th class="tr">High</th>
            <th class="tr">Medium</th>
            <th class="tr">Low</th>
            <th class="tr">Avg Score</th>
          </tr>
        </thead>
        <tbody>
          {{ range sortedProjects .ProjectBreakdown }}
          <tr>
            <td>{{ .ProjectName }}</td>
            <td class="tr">{{ .Count }}</td>
            <td class="tr dim">{{ .Critical }}</td>
            <td class="tr dim">{{ .High }}</td>
            <td class="tr dim">{{ .Medium }}</td>
            <td class="tr dim">{{ .Low }}</td>
            <td class="tr"><span class="score s-{{ scoreClass .AvgRiskScore }}">{{ printf "%.1f" .AvgRiskScore }}</span></td>
          </tr>
          {{ end }}
        </tbody>
      </table>
    </div>
  </section>

  <!-- ── Remediation Actions ───────────────────────────────────── -->
  {{ if criticalAndHigh .Findings }}
  <section id="remediation">
    <div class="sec-head">
      <h2>Remediation Actions</h2>
      <span class="sub-count">Click a row to expand details &amp; scripts</span>
    </div>
    {{ range criticalAndHigh .Findings }}
    {{ if .Remediation }}
    <div class="rem-item">
      <div class="rem-hdr {{ lower .Priority }}" onclick="toggleRem(this)">
        <span class="badge b-{{ .Priority }}">{{ .Priority }}</span>
        <div class="ri">
          <div class="rt">{{ .Category }} &mdash; {{ truncate .ResourceDisplayName 60 }}</div>
          <div class="rm">Score: {{ riskScore . }}&ensp;&middot;&ensp;{{ .FindingClass }}{{ if .ProjectDisplayName }}&ensp;&middot;&ensp;{{ .ProjectDisplayName }}{{ end }}</div>
        </div>
        <span class="rc">&#x25BC;</span>
      </div>
      <div class="rem-body">
        <div class="rem-tags">
          <span class="rem-tag"><strong>Priority</strong>{{ .Priority }}</span>
          <span class="rem-tag"><strong>Risk Score</strong>{{ riskScore . }}</span>
          <span class="rem-tag"><strong>Class</strong>{{ .FindingClass }}</span>
          {{ if .ProjectDisplayName }}<span class="rem-tag"><strong>Project</strong>{{ .ProjectDisplayName }}</span>{{ end }}
          {{ if .HasCVE }}<span class="rem-tag"><strong>CVE</strong>{{ .CVEID }} &mdash; CVSS {{ printf "%.1f" .CVSSScore }}</span>{{ end }}
        </div>
        {{ if .RiskScore }}
        <div class="rem-rationale">{{ .RiskScore.Rationale }}</div>
        {{ end }}
        <div class="rem-lbl">Summary</div>
        <p>{{ .Remediation.Summary }}</p>
        {{ if .Remediation.NextSteps }}
        <div class="rem-lbl">Next Steps</div>
        <ul>{{ range .Remediation.NextSteps }}<li>{{ . }}</li>{{ end }}</ul>
        {{ end }}
        <div class="rem-effort">
          <span class="rem-etag"><strong>Effort</strong>{{ .Remediation.EstimatedEffort }}</span>
          <span class="rem-etag"><strong>Automation</strong>{{ .Remediation.AutomationPotential }}</span>
        </div>
        {{ if .Remediation.AutomationHint }}
        <div class="rem-lbl">CLI Reference</div>
        <pre class="rem-code">{{ .Remediation.AutomationHint }}</pre>
        {{ end }}
        {{ if and (eq .Priority "CRITICAL") .Remediation.RemediationScript }}
        <div class="rem-lbl">Remediation Script ({{ .Remediation.RemediationScriptLang }})</div>
        <pre class="rem-code">{{ scriptBody . }}</pre>
        {{ end }}
      </div>
    </div>
    {{ end }}
    {{ end }}
  </section>
  {{ end }}

  <div class="footer">
    Generated by <a href="https://github.com/wanaware/GCP-Sec">GCP-Sec</a>
    &ensp;&middot;&ensp;
    {{ .GeneratedAt.UTC.Format "2006-01-02 15:04:05 UTC" }}
  </div>

</main>
</div>
<script>
function toggleRem(hdr) {
  var body = hdr.nextElementSibling;
  var open = hdr.classList.toggle('open');
  body.classList.toggle('open', open);
}
function filterTable(input, id) {
  var v = input.value.toLowerCase();
  document.querySelectorAll('#' + id + ' tbody tr').forEach(function(r) {
    r.style.display = r.textContent.toLowerCase().includes(v) ? '' : 'none';
  });
}
var secs = document.querySelectorAll('section[id]');
var links = document.querySelectorAll('nav a');
window.addEventListener('scroll', function() {
  var cur = '';
  secs.forEach(function(s) { if (window.scrollY >= s.offsetTop - 64) cur = s.id; });
  links.forEach(function(a) { a.classList.toggle('active', a.getAttribute('href') === '#' + cur); });
}, { passive: true });
</script>
</body>
</html>`

// HTMLGenerator writes an interactive HTML report.
type HTMLGenerator struct{}

// NewHTMLGenerator creates a new HTMLGenerator.
func NewHTMLGenerator() *HTMLGenerator { return &HTMLGenerator{} }

// Generate writes an HTML report for r to w.
func (g *HTMLGenerator) Generate(r *models.Report, w io.Writer) error {
	if r.GeneratedAt.IsZero() {
		r.GeneratedAt = time.Now().UTC()
	}

	funcMap := template.FuncMap{
		"pct":     func(part, total int) string { return fmt.Sprintf("%.1f", utils.SafePercentage(part, total)) },
		"inc":     func(i int) int { return i + 1 },
		"lower":   strings.ToLower,
		"truncate": utils.Truncate,
		// Risk score helpers
		"riskScore": func(f *models.Finding) string { return riskScoreStr(f) },
		"barWidth":  func(f *models.Finding) string { return barWidthStr(f) },
		"avgScore":  func(findings []*models.Finding, priority string) string { return avgScoreStr(findings, priority) },
		// CVE helper
		"cve": func(f *models.Finding) string {
			if f.HasCVE() {
				return f.CVEID
			}
			return "—"
		},
		// Findings helpers
		"priorityOrder":   func() []string { return []string{"CRITICAL", "HIGH", "MEDIUM", "LOW"} },
		"filterPriority":  filterByPriorityTmpl,
		"topFindings":     func(findings []*models.Finding, n int) []*models.Finding { return topNFindings(findings, n) },
		"topN":            func(cc []models.CategoryCount, n int) []models.CategoryCount { return topNCategories(cc, n) },
		"criticalAndHigh": criticalAndHighFindings,
		// Table sorting helpers
		"sortedCategories": sortedCategoryStats,
		"sortedProjects":   sortedProjectStats,
		// Compliance helpers
		"sortedFrameworks": sortedComplianceFrameworks,
		"topViolations":    func(vs []*models.ComplianceViolation, n int) []*models.ComplianceViolation { return topNViolations(vs, n) },
		// Score class helper (returns severity label for CSS)
		"scoreClass": func(score float64) string {
			switch {
			case score >= 75:
				return "CRITICAL"
			case score >= 55:
				return "HIGH"
			case score >= 35:
				return "MEDIUM"
			default:
				return "LOW"
			}
		},
		// Remediation script helpers
		"scriptBody": func(f *models.Finding) template.HTML {
			if f.Remediation == nil {
				return ""
			}
			return template.HTML(template.HTMLEscapeString(f.Remediation.RemediationScript))
		},
	}

	tmpl, err := template.New("html").Funcs(funcMap).Parse(htmlTemplate)
	if err != nil {
		return fmt.Errorf("parsing HTML template: %w", err)
	}

	// Sort findings by risk score descending for the tables.
	sorted := make([]*models.Finding, len(r.Findings))
	copy(sorted, r.Findings)
	sort.Slice(sorted, func(i, j int) bool {
		si, sj := 0.0, 0.0
		if sorted[i].RiskScore != nil {
			si = sorted[i].RiskScore.Total
		}
		if sorted[j].RiskScore != nil {
			sj = sorted[j].RiskScore.Total
		}
		return si > sj
	})

	rSorted := *r
	rSorted.Findings = sorted

	if err := tmpl.Execute(w, &rSorted); err != nil {
		return fmt.Errorf("executing HTML template: %w", err)
	}
	return nil
}

func barWidthStr(f *models.Finding) string {
	if f.RiskScore == nil {
		return "0"
	}
	return fmt.Sprintf("%.0f", f.RiskScore.Total)
}

// sortedComplianceFrameworks returns the compliance framework names sorted alphabetically.
func sortedComplianceFrameworks(m map[string][]*models.ComplianceViolation) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// criticalFindingsWithScript returns CRITICAL findings that have a generated remediation script.
func criticalFindingsWithScript(findings []*models.Finding) []*models.Finding {
	var out []*models.Finding
	for _, f := range findings {
		if f.Priority == "CRITICAL" && f.Remediation != nil && f.Remediation.RemediationScript != "" {
			out = append(out, f)
		}
	}
	return out
}
