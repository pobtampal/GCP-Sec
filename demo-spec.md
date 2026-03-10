# GCP Security Analyzer — Demo Specification

**Presenter**: Security Engineering Team
**Audience**: Leadership / Security Stakeholders
**Duration**: 15–20 minutes
**Date**: February 2026

---

## 1. Executive Overview

### What Is It?

GCP Security Analyzer is a **purpose-built command-line tool** that connects directly to Google Cloud's Security Command Center (SCC), fetches active security findings, and transforms raw data into **prioritized, actionable intelligence** — complete with risk scores, compliance mapping, and executable remediation scripts.

### The Problem It Solves

| Today (Manual Process) | With GCP Security Analyzer |
|------------------------|---------------------------|
| Analysts manually export CSV from SCC console | One command fetches live findings via API |
| Risk prioritization is subjective and inconsistent | Deterministic 0–100 scoring algorithm with full transparency |
| Remediation guidance is generic ("fix this misconfiguration") | Finding-specific bash/python scripts ready to execute |
| Compliance mapping requires cross-referencing multiple docs | Automatic detection across 7 frameworks (CIS, PCI-DSS, HIPAA, SOC2, ISO 27001, NIST, GDPR) |
| Reports are static spreadsheets | Interactive HTML dashboards + Markdown + JSON + CSV |
| Every report overwrites the last | Timestamped unique filenames for audit trail |

### Key Differentiators

1. **Zero-dependency analysis** — runs entirely on your workstation, no SaaS dependency
2. **Transparent scoring** — every risk score includes a full component breakdown and rationale
3. **Executable remediation** — CRITICAL findings get runnable scripts with DRY_RUN safety mode
4. **Multi-format output** — one run produces HTML dashboard, Markdown summary, JSON data, and CSV export
5. **Compliance-aware** — automatically maps findings to regulatory framework controls
6. **AI-enrichable** — optional Claude API integration for deeper CRITICAL finding analysis

---

## 2. Demo Environment Setup

### Prerequisites

```bash
# 1. Ensure Go 1.24+ is installed
go version

# 2. Build the analyzer
cd /path/to/GCP-Sec
go build -o GCP-Sec .

# 3. Authenticate to GCP (for live demo)
gcloud auth application-default login

# 4. Verify access
gcloud organizations list
```

### Demo Data Options

| Option | Command | Best For |
|--------|---------|----------|
| **Live fetch** | `./GCP-Sec fetch --org-id <ORG_ID>` | Maximum impact — real findings |
| **CSV analysis** | `./GCP-Sec analyze findings.csv` | Reliable, repeatable demo |

> **Recommendation**: Use a pre-exported CSV for a reliable demo. Have the live fetch ready as a backup to show API integration.

---

## 3. Demo Script — Step by Step

### Opening Statement (1 minute)

> *"Today I'm going to show you how we can go from thousands of raw security findings in GCP to a prioritized, actionable remediation plan — with executable fix scripts — in under 60 seconds."*

---

### Act 1: The Raw Data Problem (2 minutes)

**Show the raw CSV file:**

```bash
wc -l findings.csv          # Show the scale: thousands of rows
head -1 findings.csv         # Show the complexity: 60+ columns
```

> *"This is what our security team currently works with — [X] findings across [Y] columns. Prioritizing these manually takes hours, and the process is inconsistent between analysts. Let me show you a better way."*

---

### Act 2: One-Command Analysis (2 minutes)

**Run the analyzer:**

```bash
./GCP-Sec analyze findings.csv -v
```

**Narrate the output as it appears:**

> *"The tool is now:*
> - *Scoring each finding on a 0-to-100 scale using six weighted factors...*
> - *Detecting compliance framework violations...*
> - *Generating remediation guidance for every finding...*
> - *Building executable remediation scripts for all CRITICAL findings...*
> - *Producing reports in multiple formats..."*

**Point out the summary statistics:**

```
── Analysis Complete ──────────────────────────────────────
  Total findings:  2,847
  Critical:        142
  High:            538
  Medium:          1,203
  Low:             964
  Mean risk score: 47.32
  Risk range:      12.00 - 98.40
──────────────────────────────────────────────────────────
```

> *"In seconds, we've scored and prioritized nearly 3,000 findings. 142 are CRITICAL — those are our immediate focus."*

---

### Act 3: The Interactive Report (5 minutes)

**Open the HTML report in a browser:**

```bash
open findings-report-*.html
```

**Walk through each section:**

1. **Executive Summary** — "At a glance: total findings, severity distribution, risk score statistics, and top risk categories."

2. **Priority Breakdown** — "Each priority level has a defined SLA: CRITICAL = 24–48 hours, HIGH = 1 week. This gives operations clear timelines."

3. **Risk Scoring Methodology** — "Complete transparency. Every score is computed from six components — severity, CVSS, exploitability, finding class, resource exposure, and compliance impact — with a category weight multiplier. No black boxes."

4. **Findings Tables** — "Searchable, sortable tables for each priority level. Click any column to filter."

5. **Compliance Section** — *(if `--include-compliance` was used)* "Automatic mapping to CIS, PCI-DSS, HIPAA, SOC2, ISO 27001, NIST, and GDPR controls."

6. **Remediation Actions** — *This is the showstopper.* "Click any CRITICAL finding to expand it. You see: a summary, prioritized next steps, estimated effort, automation potential, and — most importantly — a ready-to-run remediation script."

---

### Act 4: Executable Remediation Scripts (3 minutes)

**Show the scripts directory:**

```bash
ls -la remediation-scripts/ | head -20
```

> *"Every CRITICAL finding gets a dedicated remediation script — either bash or python — tailored to the specific resource."*

**Show a script's contents:**

```bash
cat remediation-scripts/*-remediate.sh | head -40
```

**Highlight key features:**
- Finding metadata in the header (category, project, resource, risk score)
- Real `gcloud`/`gsutil`/`kubectl` commands
- DRY_RUN safety mode
- Error handling (`set -euo pipefail`)

**Demonstrate DRY_RUN mode:**

```bash
DRY_RUN=true ./remediation-scripts/<script-name>-remediate.sh
```

> *"DRY_RUN mode lets you preview exactly what the script will do — no changes made. When you're ready, remove the flag and it executes the fix. This eliminates manual command construction and reduces human error."*

---

### Act 5: Live Fetch (2 minutes — optional)

```bash
./GCP-Sec fetch --org-id <ORG_ID> --days 7 --save-csv latest-findings.csv -v
```

> *"This pulls findings directly from the Security Command Center API in real-time — no manual CSV export needed. It can be integrated into a CI/CD pipeline or scheduled cron job for continuous monitoring."*

---

### Act 6: Additional Capabilities (2 minutes)

**Filtering:**

```bash
# Show only CRITICAL and HIGH findings
./GCP-Sec analyze findings.csv -p critical,high

# Focus on a specific category
./GCP-Sec analyze findings.csv -c OPEN_FIREWALL

# Filter by risk score threshold
./GCP-Sec analyze findings.csv --min-risk-score 75
```

**Split reports by priority:**

```bash
./GCP-Sec analyze findings.csv --split-by-priority -d ./reports
# Produces: reports/findings-report-critical.md, findings-report-high.md, etc.
```

**AI Enhancement** *(if Anthropic API key is available):*

```bash
export ANTHROPIC_API_KEY="sk-ant-..."
./GCP-Sec analyze findings.csv --ai-enhance
```

> *"The AI enhancement sends CRITICAL findings to Claude for deeper analysis — context-aware remediation recommendations that go beyond template-based guidance."*

---

### Closing Statement (1 minute)

> *"To summarize: one command transforms thousands of raw SCC findings into a prioritized, scored, compliance-mapped security report with executable remediation scripts. It reduces our mean-time-to-remediate from days to hours for CRITICAL findings, ensures consistent prioritization across the team, and provides a complete audit trail with timestamped reports."*

---

## 4. Key Metrics to Highlight

| Metric | Value |
|--------|-------|
| **Analysis speed** | ~3,000 findings scored in < 10 seconds |
| **Scoring components** | 6 weighted factors + category multiplier |
| **Compliance frameworks** | 7 (CIS, PCI-DSS, HIPAA, SOC2, ISO 27001, NIST, GDPR) |
| **Script categories** | 11 (flow logs, firewall, IAM, SSL, containers, OS vulns, etc.) |
| **Output formats** | 4 (HTML, Markdown, JSON, CSV) |
| **MTTR reduction** | Manual hours → automated minutes for CRITICAL fixes |

---

## 5. Frequently Asked Questions (FAQ)

### General

**Q: What is GCP Security Analyzer?**
A: It is a command-line tool written in Go that fetches security findings from Google Cloud's Security Command Center, scores them using a multi-factor risk algorithm, maps them to compliance frameworks, generates remediation guidance, and produces interactive reports with executable fix scripts.

**Q: Why not just use the GCP Security Command Center console directly?**
A: SCC provides raw findings but lacks quantitative risk scoring, cross-framework compliance mapping, executable remediation scripts, and customizable multi-format reporting. This tool adds those layers of intelligence on top of SCC data.

**Q: Does this replace Security Command Center?**
A: No. It complements SCC by consuming its findings and adding risk scoring, prioritization, compliance mapping, and automated remediation that SCC does not provide natively.

### Risk Scoring

**Q: How are findings scored?**
A: Each finding is scored on a 0–100 scale using six weighted components:

| Component | Max Points |
|-----------|-----------|
| Base Severity (from GCP) | 40 |
| CVSS Score | 30 |
| Exploitability (in-the-wild, zero-day) | 20 |
| Finding Class (threat, vuln, misconfig) | 10 |
| Resource Exposure (public IP, internet-facing) | 10 |
| Compliance Impact (framework violations) | 10 |

A category weight multiplier (0.8x–1.2x) is applied to the raw sum. A severity floor ensures GCP's CRITICAL and HIGH designations are never downgraded.

**Q: Can the scoring weights be customized?**
A: Yes. The scoring engine accepts a configuration struct that can be tuned. Future versions will support YAML-based configuration files.

**Q: What are the priority thresholds?**
A: CRITICAL ≥ 75 | HIGH 55–74 | MEDIUM 35–54 | LOW < 35. Each priority has a defined remediation SLA: CRITICAL = 24–48 hours, HIGH = 1 week, MEDIUM = 30 days, LOW = 90 days.

**Q: Is the scoring methodology transparent?**
A: Fully. Every finding's risk score includes a component breakdown and a human-readable rationale string explaining exactly how the score was computed, including whether a severity floor was applied.

### Remediation

**Q: What findings get remediation scripts?**
A: All CRITICAL-priority findings receive executable remediation scripts (bash or python). All findings — regardless of priority — receive remediation guidance (summary, next steps, effort estimate, automation potential).

**Q: Are the scripts safe to run?**
A: Every script supports a `DRY_RUN=true` mode that previews actions without making changes. Scripts use `set -euo pipefail` for error handling and include detailed inline comments. Always review scripts before executing in production.

**Q: What categories of findings have specialized scripts?**
A: 11 categories have tailored scripts: VPC Flow Logs, Private Google Access, Bucket Logging, Audit Logging, Firewall Rule Logging, Open Firewalls, Weak SSL/TLS, Service Account Keys, IAM Anomalies, Container Vulnerabilities, and OS Vulnerabilities. All other categories receive a generic inspection script.

**Q: Can I run scripts automatically without review?**
A: The tool is designed for human-in-the-loop remediation. Scripts are generated for manual review and execution. Automated execution is possible but not recommended without a review step.

### Compliance

**Q: Which compliance frameworks are supported?**
A: CIS Benchmarks, PCI-DSS, HIPAA, SOC 2, ISO 27001, NIST 800-53, and GDPR. The tool parses compliance data from SCC findings and maps them to specific framework controls.

**Q: Does this tool certify compliance?**
A: No. It identifies and maps compliance-relevant findings to framework controls. It does not perform audits or grant certifications. Use it as evidence for audit preparation.

### Data & Security

**Q: Does any data leave our environment?**
A: By default, no. All processing happens locally. The only exception is the optional `--ai-enhance` flag, which sends CRITICAL finding summaries to the Claude API for enrichment. This feature requires explicit opt-in and an API key.

**Q: Where does the tool get its data?**
A: Two sources: (1) CSV files exported from GCP Security Command Center, or (2) live API calls to the SCC API using your GCP credentials (Application Default Credentials).

**Q: Are credentials stored by the tool?**
A: No. The tool uses GCP's standard Application Default Credentials (ADC) mechanism. No credentials are stored, logged, or transmitted by the tool itself.

### Operations

**Q: Can this be integrated into CI/CD?**
A: Yes. The tool is a single binary with exit codes (0 = success, 1 = error). It can be run in any CI/CD pipeline. The `fetch` command pulls live data and produces reports suitable for automated pipelines.

**Q: How often should we run it?**
A: Recommended cadence: daily for CRITICAL/HIGH monitoring, weekly for full analysis. The timestamped output files create a natural audit trail.

**Q: What are the infrastructure requirements?**
A: A single Go binary (~15MB). No database, no containers, no external services required. Runs on macOS, Linux, and Windows.

**Q: Does it support multiple GCP organizations?**
A: Yes. Pass different `--org-id` values to the `fetch` command. Each run produces independently named report files.

### AI Enhancement

**Q: What does `--ai-enhance` do?**
A: It sends CRITICAL finding details to the Claude API (Anthropic) for context-aware analysis. The AI provides deeper remediation recommendations, explains potential blast radius, and suggests related findings to investigate.

**Q: Is `--ai-enhance` required?**
A: No. It is entirely optional and requires an `ANTHROPIC_API_KEY` environment variable. The tool is fully functional without it.

---

## 6. Post-Demo Next Steps

1. **Pilot**: Run against one GCP organization for 2 weeks
2. **Validate**: Compare risk scores against team's manual prioritization
3. **Integrate**: Add to weekly security review workflow
4. **Automate**: Schedule daily fetch + report generation via cron or CI/CD
5. **Expand**: Enable compliance mapping and AI enrichment for deeper analysis

---

*Built with Go 1.24 | Powered by GCP Security Command Center API | Optional AI enrichment via Claude*
