# Design Specification — GCP-Sec

**Version:** 2.0
**Last Updated:** 2026-03-08

---

## 1. Purpose

GCP-Sec is a CLI tool that ingests GCP Security Command Center (SCC) findings — either from CSV exports or the live SCC API — and produces prioritized, actionable security reports. It applies a transparent, multi-factor risk scoring algorithm, detects compliance violations across seven frameworks, generates remediation guidance with automation scripts, and outputs reports in four formats.

---

## 2. Architecture Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                          CLI Layer                              │
│  cmd/analyzer/                                                  │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐          │
│  │ analyze  │ │  fetch   │ │  filter  │ │  stats   │          │
│  └────┬─────┘ └────┬─────┘ └────┬─────┘ └────┬─────┘          │
│       │             │            │             │                │
│       └─────────────┴────────────┴─────────────┘                │
│                         │                                       │
│                    pipeline.go (shared analysis pipeline)        │
└─────────────────────────┬───────────────────────────────────────┘
                          │
┌─────────────────────────▼───────────────────────────────────────┐
│                       Core Packages                             │
│                                                                 │
│  ┌────────────┐  ┌────────────┐  ┌──────────────┐              │
│  │   parser   │  │  scoring   │  │  compliance  │              │
│  │  (CSV/API) │──▶ (risk.go)  │──▶ (detector)   │              │
│  └────────────┘  └─────┬──────┘  └──────┬───────┘              │
│                        │                │                       │
│                  ┌─────▼────────────────▼──────┐                │
│                  │      remediation            │                │
│                  │  (guidance + scripts)       │                │
│                  └─────────────┬───────────────┘                │
│                               │                                 │
│                  ┌────────────▼────────────────┐                │
│                  │         report              │                │
│                  │  (MD / JSON / HTML / CSV)   │                │
│                  └────────────────────────────┘                │
│                                                                 │
│  ┌────────────┐  ┌────────────┐                                │
│  │  fetcher   │  │    llm     │  (optional AI enrichment)      │
│  │ (GCP API)  │  │ (Claude)   │                                │
│  └────────────┘  └────────────┘                                │
└─────────────────────────────────────────────────────────────────┘
                          │
┌─────────────────────────▼───────────────────────────────────────┐
│                    Internal Packages                            │
│                                                                 │
│  internal/models/          internal/utils/                      │
│  ┌──────────────┐          ┌──────────────┐                    │
│  │ Finding      │          │ Logger       │                    │
│  │ Report       │          │ Helpers      │                    │
│  │ RiskScore    │          │ Flags        │                    │
│  └──────────────┘          └──────────────┘                    │
└─────────────────────────────────────────────────────────────────┘
```

---

## 3. Data Flow

### 3.1 Analysis Pipeline

```
Input (CSV file or GCP SCC API)
  │
  ▼
Parse ── pkg/parser/csv.go or pkg/fetcher/
  │       - Column aliasing (dotted GCP paths → simple names)
  │       - Streaming row-by-row parsing
  │       - JSON field extraction (CVSS, CVE, compliances)
  │       - Produces []Finding
  │
  ▼
Score ── pkg/scoring/risk.go
  │       - 7-component risk formula (see §5)
  │       - Parallel goroutine pool (8 workers)
  │       - Priority assignment (CRITICAL/HIGH/MEDIUM/LOW)
  │       - Severity floor enforcement
  │
  ▼
Detect Compliance ── pkg/compliance/detector.go
  │       - Framework matching (CIS, PCI-DSS, HIPAA, etc.)
  │       - Violation aggregation by framework + control
  │       - Deduplication
  │
  ▼
Generate Remediation ── pkg/remediation/
  │       - Structured guidance (summary, steps, links, effort)
  │       - Automation scripts for CRITICAL findings (Bash/Python)
  │
  ▼
(Optional) AI Enrichment ── pkg/llm/enricher.go
  │       - Claude API (claude-haiku-4-5-20251001)
  │       - Parallel (4 workers), CRITICAL findings only
  │       - Graceful fallback on failure
  │
  ▼
Build Report ── pkg/report/builder.go
  │       - Aggregate statistics
  │       - Category and project breakdowns
  │       - Compliance summary
  │
  ▼
Render Output ── pkg/report/{markdown,json,html,csv}.go
          - One or more formats written to disk
```

### 3.2 Fetch Pipeline

```
GCP SCC API (organizations/{org}/sources/-/findings)
  │
  ▼
pkg/fetcher/fetcher.go
  │  - Authenticates via Application Default Credentials
  │  - Builds filter: state="ACTIVE" AND event_time >= ...
  │  - Paginates (page size 1000)
  │  - Logs progress every 500 findings
  │
  ▼
pkg/fetcher/convert.go
  │  - Converts protobuf Finding → internal models.Finding
  │
  ▼
(Optional) Save raw CSV ── --save-csv flag
  │
  ▼
Analysis Pipeline (same as §3.1 from Score onward)
```

---

## 4. Core Data Models

### 4.1 Finding (`internal/models/finding.go`)

| Field Group | Key Fields | Source |
|---|---|---|
| Identity | Name, Category, FindingClass, Type | CSV / API |
| Severity | Severity (string), State | CSV / API |
| Resource | ResourceName, ResourceType, ProjectID | CSV / API |
| Vulnerability | CVEID, CVSSScore (float64), ExploitationActivity | CSV JSON fields |
| Exposure | PublicIPAddress (bool) | CSV |
| Compliance | Compliances (string), ComplianceDetails (string) | CSV JSON fields |
| Timestamps | EventTime, CreateTime | CSV / API |
| **Computed** | RiskScore, Priority, Remediation, Violations | Scoring pipeline |

### 4.2 RiskScore (`internal/models/risk_score.go`)

```go
type RiskScore struct {
    BaseSeverity    float64  // 0-40
    CVSSComponent   float64  // 0-30
    Exploitability  float64  // 0-20
    ClassModifier   float64  // 0-10
    ExposureScore   float64  // 0-10
    ComplianceScore float64  // 0-10
    CategoryWeight  float64  // 0.8-1.2 multiplier
    Total           float64  // 0-100 final score
    Rationale       string   // Human-readable explanation
}
```

### 4.3 Report (`internal/models/report.go`)

```go
type Report struct {
    GeneratedAt       time.Time
    InputFile         string
    ParseErrors       int
    Findings          []Finding
    Stats             Stats           // Counts, risk score statistics
    ComplianceSummary map[string][]Violation
    CategoryBreakdown map[string]CategoryStats
    ProjectBreakdown  map[string]ProjectStats
}
```

---

## 5. Risk Scoring Algorithm

### Formula

```
raw = BaseSeverity + CVSSComponent + Exploitability
    + ClassModifier + ExposureScore + ComplianceScore

total = min(raw × CategoryWeight, 100)
```

### Components

| # | Component | Range | Calculation |
|---|-----------|-------|-------------|
| 1 | Base Severity | 0–40 | CRITICAL=40, HIGH=30, MEDIUM=20, LOW=10 |
| 2 | CVSS Score | 0–30 | CVSSv3 base × 3, capped at 30 |
| 3 | Exploitability | 0–20 | In-wild (+10), zero-day (+8), activity (+2–6), has CVE (+2) |
| 4 | Class Modifier | 0–10 | THREAT=10, VULNERABILITY=7, MISCONFIGURATION=5, OBSERVATION=2 |
| 5 | Exposure | 0–10 | Public IP (+5), internet-facing (+3), critical resource (+2) |
| 6 | Compliance | 0–10 | Has frameworks (+5), details (+3), audit category (+2) |
| 7 | Category Weight | ×0.8–1.2 | High-risk categories 1.2×, medium 1.0×, low 0.8× |

### Priority Thresholds

| Priority | Score Range | Remediation SLA |
|----------|-------------|-----------------|
| CRITICAL | ≥ 75 | 24 hours |
| HIGH | 55–74 | 7 days |
| MEDIUM | 35–54 | 30 days |
| LOW | < 35 | 90 days / accept risk |

### Severity Floor

A minimum score is enforced based on GCP's severity to prevent high-severity misconfiguration findings from being scored too low:

| GCP Severity | Minimum Score |
|---|---|
| CRITICAL | 60 |
| HIGH | 40 |
| MEDIUM | 20 |

---

## 6. Compliance Detection

### Supported Frameworks

CIS Benchmarks, PCI-DSS, HIPAA, SOC 2, ISO 27001, NIST CSF, GDPR

### Detection Process

1. Parse `finding.compliances` JSON array — extracts framework ID, version, control IDs
2. Parse `finding.compliance_details.frameworks` — detailed control mappings
3. Match against known framework definitions (`pkg/compliance/frameworks.go`)
4. Aggregate violations by framework and control, deduplicate
5. Count affected findings per violation

---

## 7. Report Formats

| Format | File | Use Case | Key Features |
|--------|------|----------|-------------|
| Markdown | `.md` | Human review, PRs | Executive summary, priority tables, remediation steps |
| JSON | `.json` | Automation, dashboards | Complete structured data, all score components |
| HTML | `.html` | Stakeholder sharing | Interactive dashboard, sortable tables, color-coded cards |
| CSV | `.csv` | Spreadsheets, pipelines | Original columns + computed scores |

---

## 8. CLI Commands

| Command | Purpose | Key Flags |
|---------|---------|-----------|
| `analyze` | Full analysis → report | `--formats`, `--include-remediation`, `--include-compliance`, `--split-by-priority`, `--ai-enhance` |
| `fetch` | Pull live from GCP SCC API → analyze | `--org-id`, `--days`, `--save-csv` |
| `stats` | Print summary statistics to stdout | `--verbose` |
| `filter` | Score, filter, export to CSV | `--priority`, `--category`, `--project`, `--min-risk-score` |

---

## 9. Concurrency Model

| Operation | Workers | Pattern |
|-----------|---------|---------|
| Risk scoring | 8 goroutines | Channel-based work distribution, no shared mutable state |
| LLM enrichment | 4 goroutines | Parallel API calls, CRITICAL findings only |
| CSV parsing | 1 (streaming) | Row-by-row, constant memory |

---

## 10. CI/CD Pipeline

### CI (`ci.yml`)

- **Trigger:** Push to main/master, PRs
- **Test matrix:** Go 1.21, 1.22, 1.23
- **Steps:** `go mod verify` → `go vet` → `go test` (with race detector + coverage) → build → smoke test
- **Release:** Cross-compiles for Linux/macOS/Windows on tagged pushes

### SAST (`sast.yml`)

- **Trigger:** Push to main/master, PRs
- **Parallel scan jobs:**

| Job | Tool | Output | Uploads to |
|-----|------|--------|-----------|
| gitleaks | Gitleaks | SARIF | GitHub Security tab |
| semgrep | Semgrep | SARIF | GitHub Security tab + artifact |
| trivy | Trivy | SARIF | GitHub Security tab + artifact |
| gosec | gosec | SARIF | GitHub Security tab + artifact |

- **Report job** (`report-and-notify`): Runs after all scans, consolidates results into MD + HTML reports, publishes to [sast-report repo](https://github.com/pobtampal/sast-report), sends email notification via SendGrid

---

## 11. Dependencies

### Direct

| Package | Purpose |
|---------|---------|
| `cloud.google.com/go/securitycenter` v1.38.1 | GCP SCC API client |
| `google.golang.org/api` v0.267.0 | Google API support |

### Design Principle

Core analysis logic (parsing, scoring, compliance, remediation, reporting) uses **only the Go standard library**. External dependencies are limited to GCP API integration and optional AI enrichment.

---

## 12. Security Considerations

- **No secrets in code** — Gitleaks pre-commit hook + CI scan
- **Input validation** — CSV parser handles malformed input gracefully (lazy quotes, variable fields)
- **No shell injection** — No user input passed to `exec.Command`
- **TLS enforced** — No `InsecureSkipVerify` usage (Semgrep rule)
- **Sensitive data** — Findings may contain resource names; reports should be treated as confidential
- **AI enrichment** — API key passed via environment variable, never logged

---

## 13. Performance Characteristics

| Metric | Value |
|--------|-------|
| Scoring throughput | ~500k findings/sec |
| Memory model | Streaming CSV parse (constant memory for parsing phase) |
| Parallel workers | 8 (scoring), 4 (LLM) |
| Report generation | < 1 second for 10k findings |

---

## 14. Extensibility Points

| Extension | How |
|-----------|-----|
| New compliance framework | Add to `pkg/compliance/frameworks.go` |
| New report format | Implement interface in `pkg/report/` |
| Custom scoring weights | Pass `--scoring-config <yaml>` |
| New remediation scripts | Add category handler in `pkg/remediation/scripts.go` |
| New CLI command | Add file in `cmd/analyzer/`, register in `root.go` |
