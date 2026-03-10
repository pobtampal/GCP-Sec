# GCP Security Analyzer — Architecture & End-to-End Workflow

## Table of Contents

1. [Overview](#overview)
2. [Directory Structure](#directory-structure)
3. [High-Level Data Flow](#high-level-data-flow)
4. [CLI Commands](#cli-commands)
5. [Stage 1 — Ingestion](#stage-1--ingestion)
6. [Stage 2 — Risk Scoring](#stage-2--risk-scoring)
7. [Stage 3 — Compliance Detection](#stage-3--compliance-detection)
8. [Stage 4 — Remediation Guidance](#stage-4--remediation-guidance)
9. [Stage 5 — AI Enrichment (optional)](#stage-5--ai-enrichment-optional)
10. [Stage 6 — Filtering](#stage-6--filtering)
11. [Stage 7 — Report Generation](#stage-7--report-generation)
12. [Core Data Models](#core-data-models)
13. [End-to-End Examples](#end-to-end-examples)
14. [Key Design Decisions](#key-design-decisions)

---

## Overview

GCP Security Analyzer is a command-line tool that ingests security findings from **Google Cloud Security Command Center (SCC)** — either from a CSV export or directly via the live API — and produces prioritized, enriched security reports in multiple formats (Markdown, HTML, JSON, CSV) along with executable remediation scripts.

```
Input (CSV or live SCC API)
        │
        ▼
   Parse Findings
        │
        ▼
   Risk Scoring  ──────────────────────► Priority Assignment
        │                                (CRITICAL / HIGH / MEDIUM / LOW)
        ▼
   Compliance Detection
        │
        ▼
   Remediation Guidance  (--include-remediation)
        │
        ▼
   AI Enrichment  (--ai-enhance, optional)
        │
        ▼
   Filtering  (-p, -c, --project, --min-risk-score)
        │
        ▼
   Report Generation
   (markdown + html by default; also json, csv)
        │
        ▼
   Remediation Scripts written to remediation-scripts/
```

---

## Directory Structure

```
GCP-Sec/
├── main.go                        Entry point
├── cmd/analyzer/
│   ├── root.go                    Command dispatcher & help text
│   ├── analyze.go                 "analyze" command (CSV-based)
│   ├── fetch.go                   "fetch" command (live SCC API)
│   ├── pipeline.go                Shared analysis pipeline
│   ├── filter.go                  "filter" command (CSV → filtered CSV)
│   └── stats.go                   "stats" command (console summary)
├── internal/
│   ├── models/
│   │   ├── finding.go             Finding struct + methods
│   │   ├── report.go              Report, ReportStats, Options structs
│   │   └── risk_score.go          RiskScore, ComplianceViolation, RemediationStep
│   └── utils/
│       ├── helpers.go             Math (mean, median, stddev) + string utilities
│       ├── flags.go               ExtractPositional — separates CLI positional arg from flags
│       └── logger.go              Leveled logger (Debug/Info/Warn/Error)
├── pkg/
│   ├── parser/csv.go              CSV reader + GCP column alias mapping
│   ├── scoring/
│   │   ├── risk.go                Multi-factor 0-100 scoring engine
│   │   └── priorities.go          Filter, sort, group, compute stats on findings
│   ├── compliance/
│   │   ├── detector.go            Parse compliance JSON + aggregate violations
│   │   └── frameworks.go          Known frameworks: CIS, PCI-DSS, HIPAA, SOC2, ISO 27001, NIST, GDPR
│   ├── remediation/
│   │   ├── guidance.go            Category-specific remediation steps, effort, automation hints
│   │   └── scripts.go             Bash/Python3 automation script generation
│   ├── llm/enricher.go            Optional Claude API enrichment for CRITICAL findings
│   ├── fetcher/
│   │   ├── fetcher.go             GCP SCC API client (with pagination)
│   │   └── convert.go             Protobuf → models.Finding conversion
│   └── report/
│       ├── builder.go             Aggregate findings into Report with statistics
│       ├── markdown.go            Markdown report generator
│       ├── html.go                Interactive single-file HTML report generator
│       ├── json.go                JSON export
│       └── csv.go                 CSV export
└── remediation-scripts/           Output directory for generated automation scripts
```

---

## High-Level Data Flow

```
┌─────────────────────────────────────────────────────────────────────┐
│  INPUT                                                               │
│                                                                      │
│  CSV file (gcloud scc findings export)                               │
│    OR                                                                │
│  Live GCP SCC API (requires ADC + org ID)                           │
└───────────────────────┬─────────────────────────────────────────────┘
                        │
                        ▼ pkg/parser OR pkg/fetcher
                ┌───────────────┐
                │  []*Finding   │  Raw finding structs, unscored
                └───────┬───────┘
                        │
                        ▼ pkg/scoring
                ┌───────────────────────────────┐
                │  []*Finding (scored)           │
                │  ├── RiskScore.Total (0-100)   │
                │  └── Priority (CRIT/HIGH/…)    │
                └───────┬───────────────────────┘
                        │
                        ▼ pkg/compliance
                ┌────────────────────────────────────┐
                │  []*Finding (compliance-annotated)  │
                │  └── Violations [CIS, PCI-DSS, …]  │
                └───────┬────────────────────────────┘
                        │
                        ▼ pkg/remediation  (optional)
                ┌──────────────────────────────────────────┐
                │  []*Finding (with remediation guidance)   │
                │  └── Remediation.Summary, Steps, Script  │
                └───────┬──────────────────────────────────┘
                        │
                        ▼ pkg/llm  (optional)
                ┌──────────────────────────────────────────┐
                │  []*Finding (AI-enhanced, CRITICAL only)  │
                │  └── Rationale + Script overwritten       │
                └───────┬──────────────────────────────────┘
                        │
                        ▼ cmd/analyzer.applyFilters
                ┌─────────────────────────────────┐
                │  []*Finding (filtered subset)    │
                └───────┬─────────────────────────┘
                        │
                        ▼ pkg/report/builder
                ┌─────────────────────────────────────────────────────┐
                │  *Report                                             │
                │  ├── Stats (total, critical, high, medium, low)     │
                │  ├── RiskStats (mean, median, min, max, stddev)      │
                │  ├── CategoryBreakdown (per-category counts, avg)    │
                │  ├── ProjectBreakdown  (per-project counts, avg)     │
                │  └── ComplianceSummary (per-framework violations)    │
                └───────┬─────────────────────────────────────────────┘
                        │
               ┌────────┴────────┐
               ▼                 ▼
         Markdown +        remediation-scripts/
         HTML reports      ├── <finding>-remediate.sh
         (JSON / CSV        └── <finding>-remediate.py
          optional)
```

---

## CLI Commands

All commands are accessed through the single binary:

```
GCP-Sec <command> [options]
```

### `analyze` — Primary command (CSV input)

```bash
GCP-Sec analyze <input.csv> [options]

Options:
  -o, --output <path>       Output file path; stem used for multi-format naming
  -f, --format <fmt>        Single format: markdown | html | json | csv
      --formats <list>      Comma-separated formats (e.g. markdown,html,json)
  -d, --output-dir <dir>    Output directory
  -p, --priority <list>     Filter: CRITICAL,HIGH,MEDIUM,LOW
  -c, --category <list>     Filter by finding category
      --project <list>      Filter by GCP project ID or display name
      --min-risk-score <n>  Minimum risk score (0-100)
      --max-risk-score <n>  Maximum risk score (0-100)
      --include-remediation Generate remediation steps and scripts
      --include-compliance  Include compliance framework details
      --ai-enhance          Enrich CRITICAL findings via Claude AI
      --split-by-priority   Write separate file per priority level
  -v, --verbose             Verbose logging
      --debug               Debug logging
```

**Default behavior** (no format flags): generates both `.md` and `.html` using the input filename stem.

```bash
GCP-Sec analyze findings.csv
# → findings-report.md + findings-report.html

GCP-Sec analyze findings.csv -o security-report.md
# → security-report.md + security-report.html
```

### `fetch` — Live SCC API

```bash
GCP-Sec fetch --org-id <ORG_ID> [options]

Options (in addition to all analyze options):
      --org-id <id>         GCP organization ID (required)
      --days <n>            Lookback window in days (default 7)
      --save-csv <path>     Also save raw findings as CSV
```

Requires Application Default Credentials:
```bash
gcloud auth application-default login
```

### `stats` — Console summary (no files written)

```bash
GCP-Sec stats <input.csv> [-v]
```

Prints: priority distribution, risk score statistics, top categories, top projects, compliance frameworks.

### `filter` — Export filtered CSV

```bash
GCP-Sec filter <input.csv> [filter options] -o filtered.csv
```

Applies the same filters as `analyze` but outputs CSV only.

---

## Stage 1 — Ingestion

### Path A: CSV (`pkg/parser/csv.go`)

The parser reads a CSV produced by `gcloud scc findings list --format=csv` or a manually exported file from the GCP Console.

**Column normalization:** GCP's CSV uses dotted API paths as headers. The parser maps them to short canonical names:

| CSV column (GCP API) | Canonical name |
|---|---|
| `finding.category` | `category` |
| `finding.severity` | `severity` |
| `resource.project_id` | `project_id` |
| `finding.vulnerability.cve.id` | parsed into `Finding.CVEID` |
| `finding.compliances` | parsed into `Finding.ComplianceFrameworks` |
| `finding.external_exposure.public_ip_address` | parsed into `Finding.PublicIPAddress` |

**Process:**
1. Read header row → build column-index map with alias lookups
2. For each data row: extract fields, parse JSON sub-objects, parse timestamps
3. Return `[]*models.Finding` (plus count of non-fatal parse errors)

### Path B: Live API (`pkg/fetcher/`)

`fetcher.go` connects to the GCP Security Command Center API using Application Default Credentials and lists all `ACTIVE` findings for the given organization within the specified lookback window, handling pagination automatically.

`convert.go` converts the protobuf response objects into `*models.Finding`, mapping GCP enum values to clean strings (e.g., `FINDING_CLASS_VULNERABILITY` → `VULNERABILITY`) and serializing nested protobuf fields to the JSON format the compliance detector expects.

---

## Stage 2 — Risk Scoring

**File:** `pkg/scoring/risk.go`

Every finding receives a numeric risk score from **0 to 100**. Scoring runs in parallel across 8 goroutines.

### Scoring formula

```
Total = (BaseSeverity + CVSS + Exploitability + ClassModifier + Exposure + Compliance) × CategoryWeight
```

| Component | Max pts | How it's calculated |
|---|---|---|
| **Base Severity** | 40 | CRITICAL=40, HIGH=30, MEDIUM=20, LOW=10 |
| **CVSS** | 30 | CVSS score × 3 (capped at 30) |
| **Exploitability** | 20 | In-the-wild=+10, zero-day=+8, active=+6, POC=+4, low=+2, has CVE=+2 |
| **Class Modifier** | 10 | THREAT=10, VULNERABILITY=7, MISCONFIGURATION=5, OBSERVATION=2 |
| **Exposure** | 10 | Public IP=+5, internet-facing resource=+3, critical resource type=+2 |
| **Compliance** | 10 | Has frameworks=+5, has details=+3, audit/logging category=+2 |
| **Category Weight** | ×0.8–1.2 | High-risk categories (VULN, PRIVILEGE_ESCALATION, PUBLIC…)=1.2×; medium=1.0×; low=0.8× |

### Severity floor (safety mechanism)

GCP's own severity judgment is treated as authoritative. The computed score is never allowed to fall below the band that corresponds to GCP's severity:

| GCP Severity | Minimum score enforced |
|---|---|
| CRITICAL | 75 |
| HIGH | 55 |
| MEDIUM | (no floor) |
| LOW | (no floor) |

### Priority assignment

After scoring, each finding is assigned a priority:

| Score range | Priority |
|---|---|
| 75 – 100 | CRITICAL |
| 55 – 74 | HIGH |
| 35 – 54 | MEDIUM |
| 0 – 34 | LOW |

---

## Stage 3 — Compliance Detection

**File:** `pkg/compliance/detector.go`

The detector parses two raw JSON fields on each Finding:

- `finding.compliances` — array: `[{"standard":"CIS","version":"1.2","ids":["3.1","3.2"]}]`
- `finding.compliance_details.frameworks` — array: `[{"name":"ISO27001","controls":["A.12.4"]}]`

Framework names are normalized to canonical IDs:

| Observed names | Canonical ID |
|---|---|
| CIS, CIS_BENCHMARK, CISGCP | `CIS` |
| PCI, PCIDSS, PCI_DSS | `PCI_DSS` |
| SOC2, SOC 2 | `SOC_2` |
| ISO27001, ISO 27001 | `ISO_27001` |
| NIST, NIST_CSF | `NIST` |

Results are stored on `Finding.Violations` and, after all findings are processed, aggregated into `Report.ComplianceSummary` (grouped by framework, then by control, with occurrence counts).

**Supported frameworks:** CIS Benchmarks, PCI-DSS, HIPAA, SOC 2, ISO 27001, NIST CSF, GDPR.

---

## Stage 4 — Remediation Guidance

**Files:** `pkg/remediation/guidance.go`, `pkg/remediation/scripts.go`

Activated with `--include-remediation`. Populates `Finding.Remediation` for every finding.

### Guidance fields (all findings)

| Field | Content |
|---|---|
| `Summary` | One-line fix description tailored to category |
| `EstimatedEffort` | Low / Medium / High with time estimate |
| `AutomationPotential` | Describes automation level + example gcloud command |
| `PriorityRationale` | Why this finding scored its priority (severity + CVSS + exploit + exposure + compliance) |
| `NextSteps` | Bullet list parsed from GCP's `next_steps` field |
| `ResourceLinks` | Category-specific documentation URLs |

### Automation scripts (CRITICAL findings only)

For CRITICAL findings, an executable script is generated based on the finding category:

| Category | Script type | What it does |
|---|---|---|
| VPC_FLOW_LOGS | Bash | Enables VPC flow logs on the affected subnet |
| PRIVATE_GOOGLE_ACCESS | Bash | Enables Private Google Access on subnet |
| BUCKET_LOGGING | Bash | Configures access logging on GCS bucket |
| AUDIT_LOGGING | Bash + Python3 | Merges audit config to enable data access logs |
| FIREWALL_RULE_LOGGING | Bash | Enables logging on the firewall rule |
| OPEN_FIREWALL | Bash | Restricts public access by updating firewall rule |
| WEAK_SSL_POLICY | Bash | Creates and applies a modern TLS SSL policy |
| SERVICE_ACCOUNT_KEY | Bash | Lists and rotates/deletes service account keys |
| IAM_ANOMALY | Bash | Lists IAM bindings and recent audit changes |
| CONTAINER_IMAGE_VULNERABILITY | Python3 | Queries Container Analysis, inspects affected pod |
| OS_VULNERABILITY | Python3 | Checks OS Config report, initiates patch job |
| *(default)* | Bash | Inspects resource via Cloud Asset Inventory |

All scripts include:
- A header block with finding metadata (category, priority, risk score, project, CVE/CVSS if applicable)
- Variable extraction from the GCP resource path (project, region, zone, subnet, cluster, bucket, etc.)
- `DRY_RUN=true` guard that prints what would be done without making changes
- `set -euo pipefail` for safe bash execution

Scripts are written to `remediation-scripts/<finding-id>-remediate.sh` (or `.py`) with `0755` permissions.

---

## Stage 5 — AI Enrichment (optional)

**File:** `pkg/llm/enricher.go`

Activated with `--ai-enhance` and requires the `ANTHROPIC_API_KEY` environment variable.

Processes only **CRITICAL** findings, up to 4 concurrently.

**API call:**
- Endpoint: `https://api.anthropic.com/v1/messages`
- Model: `claude-haiku-4-5-20251001`
- Max tokens: 1024, timeout: 30 seconds

**Prompt context includes:** category, severity, resource name, description, CVE ID, CVSS score, GCP's next steps.

**Requested JSON response:**
```json
{
  "risk_rationale": "2-3 sentence explanation of why this is a security risk",
  "remediation_script": "complete runnable bash or python3 script",
  "remediation_lang": "bash"
}
```

The AI output overwrites `Finding.RiskScore.Rationale` and `Finding.Remediation.RemediationScript`. If the API call fails for any reason, the original template-based content is preserved and a warning is logged — processing continues.

---

## Stage 6 — Filtering

**File:** `cmd/analyzer/analyze.go` — `applyFilters()`

Applied after scoring, compliance, and enrichment. Filters are cumulative (each applied in sequence):

| Flag | Filter behavior |
|---|---|
| `-p CRITICAL,HIGH` | Keep only findings with matching priority |
| `-c FIREWALL,IAM` | Keep only findings with matching category (case-insensitive) |
| `--project my-project` | Keep only findings where ProjectID or ProjectDisplayName matches |
| `--min-risk-score 70` | Keep only findings with RiskScore.Total ≥ 70 |
| `--max-risk-score 90` | Keep only findings with RiskScore.Total ≤ 90 |

Filtering happens after enrichment so that all findings benefit from scoring before being reduced.

---

## Stage 7 — Report Generation

**Files:** `pkg/report/`

### Report object assembly (`builder.go`)

Before writing any files, the `Builder` aggregates findings into a `*models.Report`:

- Counts per priority (critical, high, medium, low)
- Risk score statistics: mean, median, min, max, standard deviation
- Top categories ranked by finding count
- Top projects ranked by finding count
- Per-category breakdown: count per priority + average risk score
- Per-project breakdown: count per priority + average risk score
- Compliance summary (if `--include-compliance`): violations grouped by framework → control

### Output formats

| Format | File | Description |
|---|---|---|
| `markdown` | `.md` | Full report: exec summary, priority breakdown, methodology, top findings, compliance violations, detailed per-finding sections |
| `html` | `.html` | Single-file interactive report with sidebar nav, stat cards, collapsible remediation, print CSS |
| `json` | `.json` | Complete Report struct serialized as JSON |
| `csv` | `.csv` | One finding per row with all scored/annotated fields |

### Output file naming

| Scenario | Output files |
|---|---|
| `analyze findings.csv` | `findings-report.md` + `findings-report.html` |
| `analyze findings.csv -o report.md` | `report.md` + `report.html` |
| `analyze findings.csv -d ./out` | `./out/findings-report.md` + `./out/findings-report.html` |
| `analyze findings.csv --format html` | `findings-report.html` only |
| `analyze findings.csv --formats markdown,html,json` | All three files |

### Remediation scripts

Written by `report.WriteRemediationScripts()` to `remediation-scripts/` in the current directory (or output directory if `-d` is set). One file per CRITICAL finding that has a generated script.

---

## Core Data Models

### `models.Finding`

The central struct that flows through every stage:

```
Finding
├── Identification:  Name, FindingClass, FindingType, Category, State, Severity
├── Resource:        ResourceName, ResourceDisplayName, ResourceType
├── Project:         ProjectID, ProjectDisplayName
├── Timestamps:      EventTime, CreateTime
├── Description:     Description, NextSteps, ExternalURI
├── Vulnerability:   CVEID, CVSSScore, ObservedInWild, ZeroDay, ExploitActivity
├── Exposure:        PublicIPAddress
├── Compliance:      ComplianceFrameworks [], ComplianceDetails [], Violations []
└── Computed:
    ├── RiskScore     (populated by scoring engine)
    │   ├── Total (0-100)
    │   ├── Component breakdown (BaseSeverity, CVSS, Exploitability, …)
    │   └── Rationale (text, possibly AI-overwritten)
    ├── Priority      (CRITICAL / HIGH / MEDIUM / LOW)
    └── Remediation   (populated by remediation package)
        ├── Summary, EstimatedEffort, AutomationPotential
        ├── NextSteps [], ResourceLinks []
        ├── RemediationScript (bash or python3)
        └── RemediationScriptLang ("bash" or "python3")
```

### `models.Report`

The final aggregated structure written to output files:

```
Report
├── GeneratedAt, InputFile, TotalRows, ParseErrors
├── Findings []*Finding
├── Stats ReportStats
│   ├── Total, Critical, High, Medium, Low
│   ├── RiskStats (Mean, Median, Min, Max, StdDev)
│   ├── TopCategories []CategoryCount
│   └── TopProjects []ProjectCount
├── CategoryBreakdown map[category → CategoryStats]
│   └── CategoryStats: Critical, High, Medium, Low counts + AvgRiskScore
├── ProjectBreakdown map[project → ProjectStats]
│   └── ProjectStats: same as CategoryStats
└── ComplianceSummary map[framework → []*ComplianceViolation]
    └── ComplianceViolation: Framework, Control, Description, Count, Findings[]
```

---

## End-to-End Examples

### Example 1: Basic CSV analysis (default output)

```bash
GCP-Sec analyze findings.csv
```

1. `root.go` dispatches to `runAnalyze`
2. `ExtractPositional` identifies `findings.csv` as the positional argument
3. `parser.ParseFile("findings.csv")` opens the file, reads header, maps columns, parses rows → `[]*Finding`
4. `runPipeline` executes:
   - `scoring.Engine.ScoreAll()` → assigns `RiskScore` + `Priority` to every finding (8 goroutines in parallel)
   - `compliance.Detector.DetectViolations()` → parses JSON compliance fields, populates `Violations`
   - No remediation (flag not set)
   - No AI (flag not set)
   - No filters (no filter flags)
   - `report.Builder.Build()` → aggregates into `*Report`
   - `report.WriteReport(format="markdown")` → writes `findings-report.md`
   - `report.WriteReport(format="html")` → writes `findings-report.html`
5. **Output:** `findings-report.md`, `findings-report.html`

### Example 2: Full pipeline with AI enrichment

```bash
GCP-Sec analyze findings.csv \
  --include-remediation \
  --include-compliance \
  --ai-enhance \
  -o security-report.md
```

1. Parse `findings.csv` → `[]*Finding`
2. Score all findings → risk scores + priorities
3. Detect compliance violations → annotate findings
4. Generate remediation guidance for every finding
5. Generate automation scripts for CRITICAL findings
6. Call Claude API (up to 4 concurrent) for each CRITICAL finding → overwrite rationale + script
7. No filters applied
8. Build `*Report` with compliance summary included
9. Write `security-report.md` + `security-report.html`
10. Write `remediation-scripts/*.sh` and `*.py`

### Example 3: Live fetch with priority filtering

```bash
export GOOGLE_APPLICATION_CREDENTIALS=~/key.json
GCP-Sec fetch \
  --org-id 123456789012 \
  --days 14 \
  --priority critical,high \
  --include-remediation \
  -o scc-weekly.md
```

1. Connect to GCP SCC API using Application Default Credentials
2. List ACTIVE findings from the last 14 days (paginated, batch size 1000)
3. Convert protobuf findings → `[]*Finding`
4. Score all findings
5. Detect compliance
6. Generate remediation guidance + scripts
7. Apply filter: keep only CRITICAL and HIGH priority
8. Build report
9. Write `scc-weekly.md` + `scc-weekly.html`
10. Write remediation scripts for CRITICAL findings

### Example 4: Stats and filtering

```bash
# Console summary only, no files
GCP-Sec stats findings.csv -v

# Export only critical findings with score ≥ 75 to a new CSV
GCP-Sec filter findings.csv \
  --priority critical \
  --min-risk-score 75 \
  -o critical-only.csv
```

---

## Key Design Decisions

### Modular pipeline
Each stage (scoring, compliance, remediation, AI, filtering, reporting) is independently toggleable via flags. The shared `runPipeline()` function in `pipeline.go` orchestrates them so that both `analyze` and `fetch` commands benefit from the same logic.

### Severity floor
The computed multi-factor score is never allowed to downgrade a finding below the band corresponding to GCP's authoritative severity label. This preserves GCP's expert judgment while still differentiating within each severity band.

### Default output: two formats
With no format flags, the tool always generates both Markdown and HTML. This avoids the common frustration of getting only one format and having to re-run.

### Graceful degradation
- Missing CVSS / CVE / compliance data → scoring continues with those components contributing 0
- AI API failures → original template-based remediation is preserved; processing continues
- CSV parse errors → logged as warnings; valid rows still processed

### Concurrency
- Scoring: 8 worker goroutines
- AI enrichment: 4 concurrent API calls

### Single-file HTML
The HTML report embeds all CSS and JavaScript inline so it can be opened in any browser without a server or additional assets.

### Column aliasing in the CSV parser
GCP's CSV export format uses full API dotted paths (`finding.category`, `resource.project_id`). The parser's alias map handles both this format and simplified column names, making the tool work with both Console exports and `gcloud` CLI exports.
