package report

import (
	"encoding/csv"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	"github.com/wanaware/GCP-Sec/internal/models"
)

// CSVGenerator writes findings as CSV with risk score columns appended.
type CSVGenerator struct{}

// NewCSVGenerator creates a new CSVGenerator.
func NewCSVGenerator() *CSVGenerator { return &CSVGenerator{} }

// csvHeader defines the columns in the output CSV.
var csvHeader = []string{
	"name", "category", "severity", "priority", "risk_score",
	"base_severity", "cvss_component", "exploitability",
	"class_modifier", "exposure_score", "compliance_score", "category_weight",
	"finding_class", "state", "resource_name", "resource_display_name",
	"project_id", "project_display_name", "cve_id", "cvss_score",
	"observed_in_wild", "zero_day", "public_ip", "compliance_frameworks",
	"compliance_violations",    // "CIS:3.1;CIS:3.2;PCI-DSS:6.5"
	"event_time", "create_time", "description",
	"remediation_script_lang", // "bash" or "python3" — CRITICAL findings only
	"remediation_script",      // full script body — CRITICAL findings only
}

// Generate writes all findings as a prioritized CSV to w.
func (g *CSVGenerator) Generate(r *models.Report, w io.Writer) error {
	if r.GeneratedAt.IsZero() {
		r.GeneratedAt = time.Now().UTC()
	}

	// Sort by risk score descending
	findings := make([]*models.Finding, len(r.Findings))
	copy(findings, r.Findings)
	sort.Slice(findings, func(i, j int) bool {
		si, sj := 0.0, 0.0
		if findings[i].RiskScore != nil {
			si = findings[i].RiskScore.Total
		}
		if findings[j].RiskScore != nil {
			sj = findings[j].RiskScore.Total
		}
		return si > sj
	})

	cw := csv.NewWriter(w)
	if err := cw.Write(csvHeader); err != nil {
		return fmt.Errorf("writing CSV header: %w", err)
	}

	for _, f := range findings {
		row := findingToCSVRow(f)
		if err := cw.Write(row); err != nil {
			return fmt.Errorf("writing CSV row for %s: %w", f.Name, err)
		}
	}

	cw.Flush()
	return cw.Error()
}

// GenerateComplianceCSV writes a compliance violations summary CSV to w.
func (g *CSVGenerator) GenerateComplianceCSV(summary map[string][]*models.ComplianceViolation, w io.Writer) error {
	cw := csv.NewWriter(w)
	header := []string{"framework", "control", "violation_count", "finding_names"}
	if err := cw.Write(header); err != nil {
		return err
	}

	// Sort by framework then count
	type row struct {
		fw string
		v  *models.ComplianceViolation
	}
	var rows []row
	for fw, vs := range summary {
		for _, v := range vs {
			rows = append(rows, row{fw, v})
		}
	}
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].fw != rows[j].fw {
			return rows[i].fw < rows[j].fw
		}
		return rows[i].v.Count > rows[j].v.Count
	})

	for _, r := range rows {
		rec := []string{
			r.v.Framework,
			r.v.Control,
			fmt.Sprintf("%d", r.v.Count),
			strings.Join(r.v.Findings, "; "),
		}
		if err := cw.Write(rec); err != nil {
			return err
		}
	}

	cw.Flush()
	return cw.Error()
}

func findingToCSVRow(f *models.Finding) []string {
	rs := &models.RiskScore{}
	if f.RiskScore != nil {
		rs = f.RiskScore
	}

	// compliance_violations: "CIS:3.1;CIS:3.2;PCI-DSS:6.5"
	var violParts []string
	for _, v := range f.Violations {
		violParts = append(violParts, v.Framework+":"+v.Control)
	}

	// remediation script — only populated for CRITICAL findings
	scriptLang, scriptBody := "", ""
	if f.Remediation != nil {
		scriptLang = f.Remediation.RemediationScriptLang
		scriptBody = f.Remediation.RemediationScript
	}

	return []string{
		f.Name,
		f.Category,
		f.Severity,
		f.Priority,
		fmt.Sprintf("%.2f", rs.Total),
		fmt.Sprintf("%.0f", rs.BaseSeverity),
		fmt.Sprintf("%.2f", rs.CVSSComponent),
		fmt.Sprintf("%.2f", rs.Exploitability),
		fmt.Sprintf("%.0f", rs.ClassModifier),
		fmt.Sprintf("%.2f", rs.ExposureScore),
		fmt.Sprintf("%.2f", rs.ComplianceScore),
		fmt.Sprintf("%.1f", rs.CategoryWeight),
		f.FindingClass,
		f.State,
		f.ResourceName,
		f.ResourceDisplayName,
		f.ProjectID,
		f.ProjectDisplayName,
		f.CVEID,
		fmt.Sprintf("%.1f", f.CVSSScore),
		boolStr(f.ObservedInWild),
		boolStr(f.ZeroDay),
		boolStr(f.PublicIPAddress),
		strings.Join(f.ComplianceFrameworks, "; "),
		strings.Join(violParts, ";"),   // compliance_violations
		f.EventTimeRaw,
		f.CreateTimeRaw,
		f.Description,
		scriptLang, // remediation_script_lang
		scriptBody, // remediation_script (encoding/csv auto-quotes multiline content)
	}
}

func boolStr(b bool) string {
	if b {
		return "true"
	}
	return "false"
}
