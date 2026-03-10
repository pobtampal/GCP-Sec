// Package report contains generators for various output formats.
package report

import (
	"fmt"
	"io"
	"sort"
	"strings"
	"text/template"
	"time"

	"github.com/wanaware/GCP-Sec/internal/models"
	"github.com/wanaware/GCP-Sec/internal/utils"
)

const markdownTemplate = `# GCP Security Findings Analysis Report

Generated: {{ .GeneratedAt.UTC.Format "2006-01-02 15:04:05 UTC" }}
Input File: {{ .InputFile }}

---

## Executive Summary

- **Total Active Findings**: {{ .Stats.Total }}
- **Critical Priority**: {{ .Stats.Critical }} ({{ pct .Stats.Critical .Stats.Total }}%)
- **High Priority**: {{ .Stats.High }} ({{ pct .Stats.High .Stats.Total }}%)
- **Medium Priority**: {{ .Stats.Medium }} ({{ pct .Stats.Medium .Stats.Total }}%)
- **Low Priority**: {{ .Stats.Low }} ({{ pct .Stats.Low .Stats.Total }}%)

**Risk Score Statistics:**
- Mean: {{ .Stats.RiskStats.Mean }}
- Median: {{ .Stats.RiskStats.Median }}
- Range: {{ .Stats.RiskStats.Min }} - {{ .Stats.RiskStats.Max }}
- Std Dev: {{ .Stats.RiskStats.StdDev }}

**Top Risk Categories:**
{{ range $i, $c := topN .Stats.TopCategories 10 -}}
{{ inc $i }}. {{ $c.Category }} ({{ $c.Count }} findings)
{{ end }}

---

## Priority Breakdown

| Priority | Count | Percentage | Avg Risk Score | Remediation SLA |
|----------|------:|----------:|---------------:|-----------------|
| CRITICAL | {{ .Stats.Critical }} | {{ pct .Stats.Critical .Stats.Total }}% | {{ avgScore .Findings "CRITICAL" }} | 24-48 hours |
| HIGH | {{ .Stats.High }} | {{ pct .Stats.High .Stats.Total }}% | {{ avgScore .Findings "HIGH" }} | 1 week |
| MEDIUM | {{ .Stats.Medium }} | {{ pct .Stats.Medium .Stats.Total }}% | {{ avgScore .Findings "MEDIUM" }} | 30 days |
| LOW | {{ .Stats.Low }} | {{ pct .Stats.Low .Stats.Total }}% | {{ avgScore .Findings "LOW" }} | 90 days |

---

## Risk Scoring Methodology

Findings are scored on a 0-100 scale using the following components:

| Component | Max Points | Description |
|-----------|----------:|-------------|
| Base Severity | 40 | CRITICAL=40, HIGH=30, MEDIUM=20, LOW=10 |
| CVSS Score | 30 | CVSS v3 base score × 3 |
| Exploitability | 20 | In-the-wild (+10), Zero-day (+8), Activity level (+2-6) |
| Finding Class | 10 | THREAT=10, VULNERABILITY=7, MISCONFIG=5, OBSERVATION=2 |
| Resource Exposure | 10 | Public IP (+5), Internet-facing (+3), Critical resource (+2) |
| Compliance Impact | 10 | Has frameworks (+5), Details (+3), Audit category (+2) |
| Category Weight | ×0.8–1.2 | High-risk categories get 1.2× multiplier |

**Priority Thresholds:** CRITICAL ≥75 | HIGH 55–74 | MEDIUM 35–54 | LOW <35

---

## Top Findings by Priority
{{ range $priority := priorityOrder -}}
{{ $findings := filterPriority $.Findings $priority -}}
{{ if gt (len $findings) 0 }}
### {{ $priority }} Priority ({{ len $findings }} findings)

| # | Category | Resource | Risk Score | CVE | Project |
|--:|----------|----------|----------:|-----|---------|
{{ range $i, $f := topFindings $findings 20 -}}
| {{ inc $i }} | {{ $f.Category }} | {{ truncate $f.ResourceDisplayName 40 }} | {{ riskScore $f }} | {{ cve $f }} | {{ $f.ProjectDisplayName }} |
{{ end -}}
{{ end -}}
{{ end }}

---
{{ if .ComplianceSummary }}
## Compliance Framework Violations
{{ range $fw, $violations := .ComplianceSummary }}
### {{ $fw }}

- **Total Violations**: {{ len $violations }}
- **Top Violations**:
{{ range $v := topViolations $violations 5 -}}
  - {{ $v.Framework }} {{ $v.Control }}: {{ $v.Count }} finding(s)
{{ end -}}
{{ end }}

---
{{ end }}
## Category Breakdown

| Category | Total | Critical | High | Medium | Low | Avg Score |
|----------|------:|---------:|-----:|-------:|----:|----------:|
{{ range $cat := sortedCategories .CategoryBreakdown -}}
| {{ $cat.Category }} | {{ $cat.Count }} | {{ $cat.Critical }} | {{ $cat.High }} | {{ $cat.Medium }} | {{ $cat.Low }} | {{ printf "%.1f" $cat.AvgRiskScore }} |
{{ end }}

---

## Project Breakdown

| Project | Total | Critical | High | Medium | Low | Avg Score |
|---------|------:|---------:|-----:|-------:|----:|----------:|
{{ range $proj := sortedProjects .ProjectBreakdown -}}
| {{ $proj.ProjectName }} | {{ $proj.Count }} | {{ $proj.Critical }} | {{ $proj.High }} | {{ $proj.Medium }} | {{ $proj.Low }} | {{ printf "%.1f" $proj.AvgRiskScore }} |
{{ end }}

---
{{ if .Stats }}
## Remediation Actions
{{ range $f := criticalAndHigh .Findings -}}
### {{ $f.Category }} — {{ truncate $f.ResourceDisplayName 60 }}

- **Priority**: {{ $f.Priority }}
- **Risk Score**: {{ riskScore $f }}
- **Project**: {{ $f.ProjectDisplayName }}
- **Finding Class**: {{ $f.FindingClass }}
{{ if $f.HasCVE }}- **CVE**: {{ $f.CVEID }} (CVSS: {{ printf "%.1f" $f.CVSSScore }}){{ end }}
{{ if $f.RiskScore }}- **Rationale**: {{ $f.RiskScore.Rationale }}{{ end }}

{{ if $f.Remediation -}}
**Summary**: {{ $f.Remediation.Summary }}

**Next Steps**:
{{ range $f.Remediation.NextSteps -}}
- {{ . }}
{{ end -}}
**Estimated Effort**: {{ $f.Remediation.EstimatedEffort }}
**Automation Potential**: {{ $f.Remediation.AutomationPotential }}
{{ if $f.Remediation.AutomationHint -}}
{{ codeFence }}bash
{{ $f.Remediation.AutomationHint }}
{{ codeFence }}
{{ end -}}
{{ if and (eq $f.Priority "CRITICAL") ($f.Remediation.RemediationScript) -}}
**Full Remediation Script** ({{ $f.Remediation.RemediationScriptLang }}):
{{ codeFence }}{{ $f.Remediation.RemediationScriptLang }}
{{ $f.Remediation.RemediationScript }}
{{ codeFence }}
{{ end -}}
{{ end -}}

---
{{ end -}}
{{ end }}

*Report generated by [GCP-Sec](https://github.com/wanaware/GCP-Sec)*
`

// MarkdownGenerator writes Markdown-formatted reports.
type MarkdownGenerator struct{}

// NewMarkdownGenerator creates a new MarkdownGenerator.
func NewMarkdownGenerator() *MarkdownGenerator { return &MarkdownGenerator{} }

// Generate writes a Markdown report for r to w.
func (g *MarkdownGenerator) Generate(r *models.Report, w io.Writer) error {
	funcMap := template.FuncMap{
		"codeFence":        func() string { return "```" },
		"pct":              func(part, total int) string { return fmt.Sprintf("%.1f", utils.SafePercentage(part, total)) },
		"inc":              func(i int) int { return i + 1 },
		"topN":             func(cc []models.CategoryCount, n int) []models.CategoryCount { return topNCategories(cc, n) },
		"avgScore":         func(findings []*models.Finding, priority string) string { return avgScoreStr(findings, priority) },
		"filterPriority":   filterByPriorityTmpl,
		"priorityOrder":    func() []string { return []string{"CRITICAL", "HIGH", "MEDIUM", "LOW"} },
		"topFindings":      func(findings []*models.Finding, n int) []*models.Finding { return topNFindings(findings, n) },
		"truncate":         utils.Truncate,
		"riskScore":        func(f *models.Finding) string { return riskScoreStr(f) },
		"cve":              func(f *models.Finding) string { if f.HasCVE() { return f.CVEID } ; return "-" },
		"topViolations":    func(vs []*models.ComplianceViolation, n int) []*models.ComplianceViolation { return topNViolations(vs, n) },
		"sortedCategories": sortedCategoryStats,
		"sortedProjects":   sortedProjectStats,
		"criticalAndHigh":  criticalAndHighFindings,
	}

	tmpl, err := template.New("report").Funcs(funcMap).Parse(markdownTemplate)
	if err != nil {
		return fmt.Errorf("parsing markdown template: %w", err)
	}

	// Ensure GeneratedAt is set
	if r.GeneratedAt.IsZero() {
		r.GeneratedAt = time.Now().UTC()
	}

	if err := tmpl.Execute(w, r); err != nil {
		return fmt.Errorf("executing markdown template: %w", err)
	}
	return nil
}

// --- Template helpers ---

func topNCategories(cc []models.CategoryCount, n int) []models.CategoryCount {
	if n > len(cc) {
		n = len(cc)
	}
	return cc[:n]
}

func topNFindings(findings []*models.Finding, n int) []*models.Finding {
	if n > len(findings) {
		n = len(findings)
	}
	return findings[:n]
}

func topNViolations(vs []*models.ComplianceViolation, n int) []*models.ComplianceViolation {
	if n > len(vs) {
		n = len(vs)
	}
	return vs[:n]
}

func filterByPriorityTmpl(findings []*models.Finding, priority string) []*models.Finding {
	var out []*models.Finding
	for _, f := range findings {
		if f.Priority == priority {
			out = append(out, f)
		}
	}
	return out
}

func avgScoreStr(findings []*models.Finding, priority string) string {
	var scores []float64
	for _, f := range findings {
		if f.Priority == priority && f.RiskScore != nil {
			scores = append(scores, f.RiskScore.Total)
		}
	}
	if len(scores) == 0 {
		return "N/A"
	}
	return fmt.Sprintf("%.1f", utils.Mean(scores))
}

func riskScoreStr(f *models.Finding) string {
	if f.RiskScore == nil {
		return "N/A"
	}
	return fmt.Sprintf("%.2f", f.RiskScore.Total)
}

func sortedCategoryStats(m map[string]models.CategoryStats) []models.CategoryStats {
	out := make([]models.CategoryStats, 0, len(m))
	for _, v := range m {
		out = append(out, v)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Count > out[j].Count })
	return out
}

func sortedProjectStats(m map[string]models.ProjectStats) []models.ProjectStats {
	out := make([]models.ProjectStats, 0, len(m))
	for _, v := range m {
		out = append(out, v)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Count > out[j].Count })
	return out
}

func criticalAndHighFindings(findings []*models.Finding) []*models.Finding {
	var out []*models.Finding
	for _, f := range findings {
		if f.Priority == "CRITICAL" || f.Priority == "HIGH" {
			out = append(out, f)
		}
	}
	// Limit to top 30 for readability
	if len(out) > 30 {
		out = out[:30]
	}
	return out
}

// StatsMarkdown writes just the stats section.
func StatsMarkdown(r *models.Report, w io.Writer) error {
	fmt.Fprintf(w, "# GCP Security Findings Statistics\n\n")
	fmt.Fprintf(w, "Generated: %s\n\n", r.GeneratedAt.UTC().Format("2006-01-02 15:04:05 UTC"))
	fmt.Fprintf(w, "| Metric | Value |\n|--------|------:|\n")
	fmt.Fprintf(w, "| Total Findings | %d |\n", r.Stats.Total)
	fmt.Fprintf(w, "| Critical | %d (%.1f%%) |\n", r.Stats.Critical, utils.SafePercentage(r.Stats.Critical, r.Stats.Total))
	fmt.Fprintf(w, "| High | %d (%.1f%%) |\n", r.Stats.High, utils.SafePercentage(r.Stats.High, r.Stats.Total))
	fmt.Fprintf(w, "| Medium | %d (%.1f%%) |\n", r.Stats.Medium, utils.SafePercentage(r.Stats.Medium, r.Stats.Total))
	fmt.Fprintf(w, "| Low | %d (%.1f%%) |\n", r.Stats.Low, utils.SafePercentage(r.Stats.Low, r.Stats.Total))
	fmt.Fprintf(w, "| Mean Risk Score | %.2f |\n", r.Stats.RiskStats.Mean)
	fmt.Fprintf(w, "| Median Risk Score | %.2f |\n", r.Stats.RiskStats.Median)
	fmt.Fprintf(w, "| Risk Score Range | %.2f - %.2f |\n", r.Stats.RiskStats.Min, r.Stats.RiskStats.Max)

	fmt.Fprintf(w, "\n## Top Categories\n\n")
	for i, c := range r.Stats.TopCategories {
		if i >= 15 {
			break
		}
		fmt.Fprintf(w, "%d. %s (%d)\n", i+1, c.Category, c.Count)
	}

	// Print compliance summary if available
	if len(r.ComplianceSummary) > 0 {
		fmt.Fprintf(w, "\n## Compliance Frameworks Detected\n\n")
		fws := make([]string, 0, len(r.ComplianceSummary))
		for fw := range r.ComplianceSummary {
			fws = append(fws, fw)
		}
		sort.Strings(fws)
		for _, fw := range fws {
			fmt.Fprintf(w, "- **%s**: %d violations\n", fw, len(r.ComplianceSummary[fw]))
		}
	}
	_ = strings.TrimSpace // suppress unused import
	return nil
}
