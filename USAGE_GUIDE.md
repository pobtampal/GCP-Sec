# GCP Security Analyzer — Usage Guide

This guide covers how to configure, run, and interpret results from the GCP Security Analyzer tool.

---

## Table of Contents

1. [Prerequisites](#1-prerequisites)
2. [Installation](#2-installation)
3. [Configuration](#3-configuration)
   - [GCP Authentication (for `fetch` command)](#gcp-authentication-for-fetch-command)
   - [AI Enrichment (optional)](#ai-enrichment-optional)
   - [Finding Your GCP Organization ID](#finding-your-gcp-organization-id)
4. [Running the Tool](#4-running-the-tool)
   - [Option A: Fetch Live from GCP SCC API](#option-a-fetch-live-from-gcp-scc-api-fetch-command)
   - [Option B: Analyze an Exported CSV](#option-b-analyze-an-exported-csv-analyze-command)
   - [Exporting CSV from GCP (manual)](#exporting-csv-from-gcp-manual)
5. [Understanding the Results](#5-understanding-the-results)
   - [Terminal Summary](#terminal-summary)
   - [Report Sections](#report-sections)
   - [Risk Scoring](#risk-scoring)
   - [Priority Levels](#priority-levels)
6. [Advanced Usage](#6-advanced-usage)
   - [Output Formats](#output-formats)
   - [Filtering](#filtering)
   - [Multi-Format Output](#multi-format-output)
   - [Remediation Scripts](#remediation-scripts)
   - [AI-Enhanced Analysis](#ai-enhanced-analysis)
7. [Makefile Shortcuts](#7-makefile-shortcuts)
8. [Troubleshooting](#8-troubleshooting)

---

## 1. Prerequisites

- **Go 1.24+** installed ([download](https://go.dev/dl/))
- **Google Cloud SDK** (`gcloud`) installed ([install guide](https://cloud.google.com/sdk/docs/install))
- A GCP organization with Security Command Center (SCC) enabled
- IAM permissions: `securitycenter.findings.list` on the organization

---

## 2. Installation

```bash
# Clone the repository
git clone https://github.com/wanaware/GCP-Sec.git
cd GCP-Sec

# Build the binary
make build
# Binary is at: ./dist/GCP-Sec

# Or install to your GOPATH/bin
make install
```

Verify the installation:

```bash
./dist/GCP-Sec version
# Output: GCP-Sec v1.0.0

./dist/GCP-Sec help
```

---

## 3. Configuration

### GCP Authentication (for `fetch` command)

The `fetch` command uses **Application Default Credentials (ADC)** to authenticate with the GCP Security Command Center API. No API keys or service account JSON files are needed if you're logged in with `gcloud`.

**Step 1: Log in with your GCP account**

```bash
gcloud auth application-default login
```

This opens a browser window to authenticate. Once complete, credentials are cached locally and the tool will use them automatically.

**Step 2: Verify your access**

```bash
# Check that you're authenticated
gcloud auth list

# Verify you can access the SCC API for your org
gcloud scc findings list organizations/YOUR_ORG_ID --limit=1
```

**Using a Service Account (CI/CD or headless environments):**

```bash
# Option 1: Activate a service account
gcloud auth activate-service-account --key-file=/path/to/sa-key.json

# Option 2: Set the environment variable directly
export GOOGLE_APPLICATION_CREDENTIALS=/path/to/sa-key.json
```

The service account needs the `Security Center Findings Viewer` role (`roles/securitycenter.findingsViewer`) at the organization level.

### AI Enrichment (optional)

To enable AI-powered enrichment of CRITICAL findings using Claude, set your Anthropic API key:

```bash
export ANTHROPIC_API_KEY="sk-ant-..."
```

Then add `--ai-enhance` to any `analyze` or `fetch` command. This is optional and the tool works fully without it.

### Finding Your GCP Organization ID

```bash
gcloud organizations list
```

Output:

```
DISPLAY_NAME       ID             DIRECTORY_CUSTOMER_ID
My Organization    123456789      C0xxxxxxx
```

The `ID` column is your organization ID. Use this with `--org-id`.

---

## 4. Running the Tool

### Option A: Fetch Live from GCP SCC API (`fetch` command)

This is the recommended approach. It fetches active findings directly from the GCP Security Command Center API and runs the full analysis pipeline in one step.

**Basic usage — fetch last 7 days:**

```bash
./dist/GCP-Sec fetch \
  --org-id 123456789 \
  -o report.md \
  --verbose
```

**Fetch last 30 days with remediation and compliance:**

```bash
./dist/GCP-Sec fetch \
  --org-id 123456789 \
  --days 30 \
  -o report.md \
  --include-remediation \
  --include-compliance \
  --verbose
```

**Fetch and also save raw findings as CSV for later use:**

```bash
./dist/GCP-Sec fetch \
  --org-id 123456789 \
  --days 14 \
  -o report.md \
  --save-csv raw-findings.csv \
  --include-remediation
```

**Fetch-specific flags:**

| Flag | Default | Description |
|------|---------|-------------|
| `--org-id <id>` | (required) | GCP organization ID |
| `--days <n>` | 7 | How many days back to look for active findings |
| `--save-csv <path>` | (none) | Save the scored findings as a CSV file |

All analysis flags (`-o`, `-f`, `--priority`, `--include-remediation`, etc.) also work with `fetch`.

### Option B: Analyze an Exported CSV (`analyze` command)

If you already have a CSV export from GCP SCC, use the `analyze` command:

```bash
./dist/GCP-Sec analyze findings.csv -o report.md --verbose
```

**With all the bells and whistles:**

```bash
./dist/GCP-Sec analyze findings.csv \
  -o report.md \
  --include-remediation \
  --include-compliance \
  --verbose
```

The CSV parser supports both formats automatically:
- **Bare column names**: `name`, `severity`, `category`, `state` (manual exports)
- **Dotted GCP API names**: `finding.name`, `finding.severity`, `finding.category` (gcloud exports)

### Exporting CSV from GCP (manual)

If you prefer to export the CSV manually before analyzing:

```bash
gcloud scc findings list organizations/123456789/sources/- \
  --filter='state="ACTIVE"' \
  --format=csv \
  > findings.csv
```

Then analyze with:

```bash
./dist/GCP-Sec analyze findings.csv -o report.md
```

---

## 5. Understanding the Results

### Terminal Summary

After every run, a summary is printed to the terminal:

```
── Analysis Complete ──────────────────────────────────────
  Total findings:  17
  Critical:        5
  High:            3
  Medium:          1
  Low:             8
  Mean risk score: 49.40
  Risk range:      12.00 - 100.00
──────────────────────────────────────────────────────────

Report written to: report.md
```

### Report Sections

The generated report (Markdown by default) contains the following sections:

| Section | What It Shows |
|---------|---------------|
| **Executive Summary** | Total findings, breakdown by priority, risk score statistics, top risk categories |
| **Priority Breakdown** | Table with count, percentage, average risk score, and SLA per priority level |
| **Risk Scoring Methodology** | Explains how the 0-100 risk score is calculated |
| **Top Findings by Priority** | Tables of findings grouped by CRITICAL, HIGH, MEDIUM, LOW |
| **Category Breakdown** | How many findings per category (e.g., CONTAINER_IMAGE_VULNERABILITY) |
| **Project Breakdown** | Findings per GCP project |
| **Remediation Actions** | (with `--include-remediation`) Detailed steps per finding with rationale |

### Risk Scoring

Each finding gets a risk score from 0 to 100 based on multiple factors:

| Component | Max Points | How It Works |
|-----------|----------:|--------------|
| Base Severity | 40 | CRITICAL=40, HIGH=30, MEDIUM=20, LOW=10 |
| CVSS Score | 30 | CVSS v3 base score multiplied by 3 |
| Exploitability | 20 | In-the-wild (+10), Zero-day (+8), exploit activity (+2-6) |
| Finding Class | 10 | THREAT=10, VULNERABILITY=7, MISCONFIGURATION=5, OBSERVATION=2 |
| Resource Exposure | 10 | Public IP (+5), internet-facing (+3), critical resource (+2) |
| Compliance Impact | 10 | Has frameworks (+5), details (+3), audit category (+2) |
| Category Weight | x0.8-1.2 | High-risk categories (e.g., container vulns) get a 1.2x multiplier |

### Priority Levels

The risk score maps to priority levels used for SLA tracking:

| Priority | Score Range | Suggested SLA |
|----------|------------|---------------|
| **CRITICAL** | 75 - 100 | 24-48 hours |
| **HIGH** | 55 - 74 | 1 week |
| **MEDIUM** | 35 - 54 | 30 days |
| **LOW** | 0 - 34 | 90 days |

---

## 6. Advanced Usage

### Output Formats

The tool supports four output formats:

```bash
# Markdown (default)
./dist/GCP-Sec analyze findings.csv -f markdown -o report.md

# JSON (machine-readable)
./dist/GCP-Sec analyze findings.csv -f json -o report.json

# HTML (browser-viewable)
./dist/GCP-Sec analyze findings.csv -f html -o report.html

# CSV (spreadsheet-friendly)
./dist/GCP-Sec analyze findings.csv -f csv -o report.csv
```

### Filtering

Filter findings before report generation:

```bash
# Only critical and high priority findings
./dist/GCP-Sec fetch --org-id 123456789 --priority critical,high -o critical-report.md

# Only container vulnerabilities
./dist/GCP-Sec fetch --org-id 123456789 --category CONTAINER_IMAGE_VULNERABILITY -o vulns.md

# Only a specific project
./dist/GCP-Sec fetch --org-id 123456789 --project prod-project -o prod-report.md

# Filter by risk score range
./dist/GCP-Sec fetch --org-id 123456789 --min-risk-score 75 -o critical-only.md
```

### Multi-Format Output

Generate reports in multiple formats at once:

```bash
# Generate markdown, JSON, and HTML in the reports/ directory
./dist/GCP-Sec fetch --org-id 123456789 \
  --formats markdown,json,html \
  --output-dir ./reports

# Split by priority level (one file per priority)
./dist/GCP-Sec fetch --org-id 123456789 \
  --formats markdown \
  --output-dir ./reports \
  --split-by-priority
```

### Remediation Scripts

When `--include-remediation` is used, the tool also generates per-finding shell scripts in a `remediation-scripts/` subdirectory:

```bash
./dist/GCP-Sec fetch --org-id 123456789 \
  -o report.md \
  --include-remediation

# Output:
#   Report written to: report.md
#   Script: ./remediation-scripts/fix-PUBLIC_BUCKET_ACL-prod-sensitive-bucket.sh
#   Script: ./remediation-scripts/fix-OPEN_FIREWALL_TO_PUBLIC-allow-rdp-all.sh
#   [2 remediation script(s) in ./remediation-scripts/]
```

### AI-Enhanced Analysis

Enrich CRITICAL findings with AI-generated context using Claude:

```bash
export ANTHROPIC_API_KEY="sk-ant-..."

./dist/GCP-Sec fetch --org-id 123456789 \
  -o report.md \
  --ai-enhance \
  --include-remediation
```

This adds detailed AI-generated remediation guidance to each CRITICAL finding in the report.

---

## 7. Makefile Shortcuts

For convenience, common workflows are available as Makefile targets:

```bash
# Build the binary
make build

# Run all tests
make test

# Analyze the bundled sample CSV
make run-sample

# Fetch live from GCP SCC (set ORG_ID, optional DAYS)
make run-fetch ORG_ID=123456789
make run-fetch ORG_ID=123456789 DAYS=30

# Generate reports in all formats from sample data
make run-all-formats

# Show quick stats for sample data
make stats-sample

# Run tests with coverage report
make test-cover

# List all available targets
make help
```

---

## 8. Troubleshooting

### "could not create SCC client" error

```
Error: could not create SCC client (run 'gcloud auth application-default login' if not authenticated)
```

**Fix:** Run `gcloud auth application-default login` and complete the browser authentication flow.

### "permission denied" or "403" errors

Your account or service account lacks the required IAM permissions.

**Fix:** Grant the `Security Center Findings Viewer` role at the org level:

```bash
gcloud organizations add-iam-policy-binding 123456789 \
  --member="user:you@example.com" \
  --role="roles/securitycenter.findingsViewer"
```

### Zero findings returned

- Check that the `--days` window is large enough. Try `--days 90`.
- Verify SCC is enabled for the organization in the GCP Console.
- Verify the org ID is correct: `gcloud organizations list`.
- Check that active findings exist: `gcloud scc findings list organizations/YOUR_ORG_ID/sources/- --filter='state="ACTIVE"' --limit=5`.

### CSV parsing shows "0 Critical" despite GCP showing Critical findings

This was a known bug that has been fixed. The parser now correctly handles both:
- Bare column names (`severity`, `category`, `state`)
- Dotted GCP API names (`finding.severity`, `finding.category`, `finding.state`)

If you're still seeing this, make sure you've rebuilt the binary with `make build`.

### "ANTHROPIC_API_KEY is not set" warning

This only appears when `--ai-enhance` is used. Set the key:

```bash
export ANTHROPIC_API_KEY="sk-ant-..."
```

Or simply remove `--ai-enhance` if you don't need AI enrichment.
