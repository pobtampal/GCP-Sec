# gcp-security-analyzer

A production-ready Go CLI for analyzing [GCP Security Command Center](https://cloud.google.com/security-command-center) findings exported as CSV. It applies a multi-factor risk scoring algorithm, detects compliance violations, generates remediation guidance, and produces reports in Markdown, JSON, HTML, and CSV formats.

**🔒 Integrated SAST security scanning** — Automated secret detection, static code analysis, dependency vulnerability scanning, and filesystem scanning via GitHub Actions.

---

## Features

- **Multi-factor risk scoring** — 0–100 scale combining severity, CVSS, exploitability, resource exposure, compliance impact, and category weight
- **Priority assignment** — CRITICAL / HIGH / MEDIUM / LOW with recommended remediation SLAs
- **Compliance detection** — CIS, PCI-DSS, HIPAA, SOC 2, ISO 27001, NIST, GDPR
- **Remediation guidance** — Structured next steps, automation hints, effort estimates
- **Multiple output formats** — Markdown, JSON, HTML (interactive dashboard), CSV
- **Powerful filtering** — By priority, category, project, risk score range
- **High performance** — Parallel scoring with goroutines, handles 100k+ rows
- **Zero mandatory dependencies** — Uses only the Go standard library

---

## Quick Start

```bash
# Build
make build

# Analyze your findings
./dist/gcp-security-analyzer analyze my-findings.csv

# Full report with remediation and compliance details
./dist/gcp-security-analyzer analyze my-findings.csv \
  --output security-report.md \
  --include-remediation \
  --include-compliance

# Generate all formats at once
./dist/gcp-security-analyzer analyze my-findings.csv \
  --output-dir ./reports \
  --formats markdown,json,html,csv \
  --include-remediation \
  --include-compliance

# Quick statistics summary
./dist/gcp-security-analyzer stats my-findings.csv

# Filter and export high/critical findings to CSV
./dist/gcp-security-analyzer filter my-findings.csv \
  --priority high,critical \
  --output high-critical.csv
```

---

## Security

This repository integrates four automated SAST checks that run on every push and pull request via GitHub Actions (`.github/workflows/sast.yml`).

| Check | Tool | What it catches |
|---|---|---|
| Secret scanning | Gitleaks | Hardcoded API keys, private keys, GCP credentials |
| Static code analysis | Semgrep | Injection flaws, TLS misconfigs, sensitive data in logs |
| Dependency CVEs | govulncheck | Known CVEs in Go module dependencies |
| Filesystem / dep scan | Trivy | CVEs in Go dependencies and OS packages |

Findings appear in the **Security → Code scanning** tab of this repository. Full JSON/SARIF reports for every build are stored in the GCS bucket configured via `SAST_REPORT_BUCKET`.

### Running scans locally

```bash
# Install hooks (run once per clone)
make setup-hooks

# Run all SAST tools
make sast

# Run individual tools
make gitleaks
make semgrep
make govulncheck
make trivy-fs
```

To install the required tools:

```bash
brew install gitleaks trivy          # macOS
pip install semgrep                  # all platforms
go install golang.org/x/vuln/cmd/govulncheck@latest
```

---

## Installation

### Build from source (recommended)

```bash
git clone https://github.com/wanaware/gcp-security-analyzer.git
cd gcp-security-analyzer
make build               # output: ./dist/gcp-security-analyzer
make install             # installs to $GOPATH/bin
```

### Using `go install`

```bash
go install github.com/wanaware/gcp-security-analyzer@latest
```

---

## Exporting Findings from GCP Security Command Center

In the GCP Console:

1. Navigate to **Security Command Center → Findings**
2. Apply your desired filters (e.g., State = ACTIVE)
3. Click **Export → Export to CSV**
4. Download the CSV file

Alternatively, use the `gcloud` CLI:

```bash
gcloud scc findings list YOUR_ORG_ID \
  --format=csv \
  --filter="state=ACTIVE" \
  > findings.csv
```

---

## Commands

### `analyze` — Full analysis and report generation

```
gcp-security-analyzer analyze <input.csv> [options]

Options:
  -o, --output string           Output file path (default: report.md)
  -f, --format string           Output format: markdown, json, html, csv (default: markdown)
  -d, --output-dir string       Output directory (when using --formats)
      --formats string          Comma-separated formats: markdown,json,html,csv
  -p, --priority string         Filter by priority: critical,high,medium,low
  -c, --category string         Filter by category (comma-separated)
      --project string          Filter by GCP project ID (comma-separated)
      --split-by-priority       Generate separate report files per priority level
      --include-remediation     Include detailed remediation steps
      --include-compliance      Include compliance violation details
      --min-risk-score float    Minimum risk score to include (default: 0)
      --max-risk-score float    Maximum risk score to include (default: 100)
  -v, --verbose                 Verbose logging
      --debug                   Debug logging
```

**Examples:**

```bash
# Markdown report (default)
gcp-security-analyzer analyze findings.csv

# JSON report for automation/pipelines
gcp-security-analyzer analyze findings.csv -f json -o findings-report.json

# HTML interactive dashboard
gcp-security-analyzer analyze findings.csv -f html -o dashboard.html

# Only HIGH and CRITICAL findings
gcp-security-analyzer analyze findings.csv -p high,critical -o high-risk.md

# Generate split files per priority
gcp-security-analyzer analyze findings.csv \
  --output-dir ./reports \
  --formats markdown \
  --split-by-priority

# Only findings with risk score > 50
gcp-security-analyzer analyze findings.csv --min-risk-score 50

# Filter by GCP project
gcp-security-analyzer analyze findings.csv --project my-project-id
```

---

### `stats` — Statistics summary

```
gcp-security-analyzer stats <input.csv> [options]

Options:
  -v, --verbose     Verbose logging
```

Prints a summary to stdout showing:
- Priority distribution (CRITICAL/HIGH/MEDIUM/LOW counts and percentages)
- Risk score statistics (mean, median, std dev, range)
- Top 10 finding categories
- Compliance frameworks detected
- Top projects by finding count

---

### `filter` — Filter and export to CSV

```
gcp-security-analyzer filter <input.csv> [options]

Options:
  -p, --priority string         Filter by priority (comma-separated)
  -c, --category string         Filter by category (comma-separated)
      --project string          Filter by GCP project
      --min-risk-score float    Minimum risk score
      --max-risk-score float    Maximum risk score
  -o, --output string           Output CSV file (default: stdout)
```

**Examples:**

```bash
# Export high/critical findings to a new CSV
gcp-security-analyzer filter findings.csv -p high,critical -o critical.csv

# Export only container vulnerabilities
gcp-security-analyzer filter findings.csv \
  -c CONTAINER_IMAGE_VULNERABILITY \
  -o container-vulns.csv

# Pipe to other tools
gcp-security-analyzer filter findings.csv -p critical | wc -l
```

---

## Report Formats

### Markdown (`.md`)

The primary human-readable format. Includes:
- Executive summary with key metrics
- Risk scoring methodology overview
- Priority distribution table with Remediation SLAs
- Top findings per priority level (tables)
- Compliance framework violations
- Category and project breakdowns
- Detailed remediation steps for HIGH/CRITICAL findings (with `--include-remediation`)

### JSON (`.json`)

Machine-readable, complete structured output. Ideal for:
- Integration with dashboards (Grafana, Looker)
- Feeding into ticketing systems (Jira, ServiceNow)
- Custom automation and alerting pipelines

```json
{
  "generated_at": "2024-01-17T10:00:00Z",
  "input_file": "findings.csv",
  "stats": { "total": 1860, "critical": 0, "high": 91 },
  "findings": [
    {
      "name": "organizations/123/sources/456/findings/abc",
      "category": "CONTAINER_IMAGE_VULNERABILITY",
      "priority": "HIGH",
      "risk_score": { "total": 58.80, "base_severity": 30, "cvss_component": 22.5 }
    }
  ]
}
```

### HTML (`.html`)

An interactive, self-contained HTML dashboard with:
- Summary metrics cards (colour-coded by severity)
- Sortable/filterable findings table (client-side JavaScript filter)
- Category breakdown table
- Compliance violations table

### CSV (`.csv`)

Findings exported with all original columns **plus** computed columns:
- `priority` — Assigned priority (CRITICAL/HIGH/MEDIUM/LOW)
- `risk_score` — Final composite risk score
- `base_severity`, `cvss_component`, `exploitability`, `class_modifier`, `exposure_score`, `compliance_score`, `category_weight` — Score component breakdown

---

## Risk Scoring

See [METHODOLOGY.md](METHODOLOGY.md) for the full scoring algorithm documentation.

**Summary:**

| Component | Max Points |
|-----------|----------:|
| Base Severity (CRITICAL=40, HIGH=30…) | 40 |
| CVSS v3 score × 3 | 30 |
| Exploitability (in-wild, zero-day…) | 20 |
| Finding Class (THREAT=10, VULN=7…) | 10 |
| Resource Exposure (public IP, internet-facing) | 10 |
| Compliance Impact | 10 |
| **Category Weight multiplier** | 0.8–1.2× |

**Priority thresholds:** CRITICAL ≥75 | HIGH 55–74 | MEDIUM 35–54 | LOW <35

---

## Compliance Frameworks Supported

| Framework | ID Used |
|-----------|---------|
| CIS Benchmarks | `CIS` |
| PCI-DSS | `PCI-DSS` |
| HIPAA | `HIPAA` |
| SOC 2 | `SOC2` |
| ISO 27001 | `ISO27001` |
| NIST CSF | `NIST` |
| GDPR | `GDPR` |

Compliance data is extracted from:
- `finding.compliances` — JSON array of framework entries
- `finding.compliance_details.frameworks` — Detailed control mappings
- `finding.compliance_details.cloud_control.*` — Cloud-specific control IDs

---

## Development

```bash
# Run all tests
make test

# Tests with coverage report
make test-cover

# Benchmarks
make bench

# Lint
make lint

# Format code
make fmt

# Run against sample data
make run-sample

# Generate all format reports from sample data
make run-all-formats
```

### Project Structure

```
gcp-security-analyzer/
├── main.go                     # Entry point
├── go.mod
├── Makefile
├── README.md
├── METHODOLOGY.md
├── cmd/analyzer/               # CLI commands
│   ├── root.go                 # Entry dispatcher and usage
│   ├── analyze.go              # analyze command
│   ├── filter.go               # filter command
│   └── stats.go                # stats command
├── pkg/
│   ├── parser/csv.go           # CSV parser
│   ├── scoring/
│   │   ├── risk.go             # Risk scoring engine
│   │   └── priorities.go       # Filtering and grouping helpers
│   ├── compliance/
│   │   ├── detector.go         # Violation detection and aggregation
│   │   └── frameworks.go       # Known framework definitions
│   ├── remediation/guidance.go # Remediation step generation
│   └── report/
│       ├── builder.go          # Report assembly
│       ├── markdown.go         # Markdown generator
│       ├── json.go             # JSON generator
│       ├── html.go             # HTML generator
│       └── csv.go              # CSV generator
├── internal/
│   ├── models/                 # Core data structures
│   └── utils/                  # Shared utilities (logger, helpers)
└── testdata/
    └── sample-findings.csv     # Sample CSV for testing
```

---

## Performance

The tool is designed to handle large GCP exports efficiently:

- **Parallel scoring**: Risk score calculations run across up to 8 goroutines
- **Streaming parser**: CSV is read row-by-row, not loaded entirely into memory
- **Benchmarks**: ~500k findings/second on a modern laptop (scoring only)

```bash
# Run benchmarks
go test ./pkg/scoring/... -bench=. -benchmem
```

---

## Contributing

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/my-feature`
3. Make your changes with tests: `make test`
4. Submit a pull request

Please ensure `make lint` and `make test` pass before submitting.

---

## License

MIT License — see [LICENSE](LICENSE) for details.

