// Package scoring implements the multi-factor risk scoring algorithm.
package scoring

import (
	"fmt"
	"strings"

	"github.com/wanaware/GCP-Sec/internal/models"
	"github.com/wanaware/GCP-Sec/internal/utils"
)

// ScoringConfig holds weights for each scoring component.
// It can be overridden via a YAML configuration file.
type ScoringConfig struct {
	// Base severity points
	CriticalBase float64 `yaml:"critical_base"`
	HighBase     float64 `yaml:"high_base"`
	MediumBase   float64 `yaml:"medium_base"`
	LowBase      float64 `yaml:"low_base"`

	// Component caps
	CVSSMax          float64 `yaml:"cvss_max"`
	ExploitMax       float64 `yaml:"exploit_max"`
	ExposureMax      float64 `yaml:"exposure_max"`
	ComplianceMax    float64 `yaml:"compliance_max"`

	// Category weight multipliers
	HighRiskWeight   float64 `yaml:"high_risk_weight"`
	MedRiskWeight    float64 `yaml:"med_risk_weight"`
	LowRiskWeight    float64 `yaml:"low_risk_weight"`
}

// DefaultConfig returns the default scoring configuration.
func DefaultConfig() ScoringConfig {
	return ScoringConfig{
		CriticalBase:   40,
		HighBase:       30,
		MediumBase:     20,
		LowBase:        10,
		CVSSMax:        30,
		ExploitMax:     20,
		ExposureMax:    10,
		ComplianceMax:  10,
		HighRiskWeight: 1.2,
		MedRiskWeight:  1.0,
		LowRiskWeight:  0.8,
	}
}

// Engine calculates risk scores for findings.
type Engine struct {
	cfg    ScoringConfig
	logger *utils.Logger
}

// NewEngine creates a new scoring Engine with the given configuration.
func NewEngine(cfg ScoringConfig, logger *utils.Logger) *Engine {
	if logger == nil {
		logger = utils.DefaultLogger
	}
	return &Engine{cfg: cfg, logger: logger}
}

// Score calculates and attaches a RiskScore to the finding.
// It is safe to call concurrently.
func (e *Engine) Score(f *models.Finding) *models.RiskScore {
	rs := &models.RiskScore{}

	rs.BaseSeverity = e.baseSeverityScore(f)
	rs.CVSSComponent = e.cvssScore(f)
	rs.Exploitability = e.exploitabilityScore(f)
	rs.ClassModifier = e.classModifierScore(f)
	rs.ExposureScore = e.exposureScore(f)
	rs.ComplianceScore = e.complianceScore(f)
	rs.CategoryWeight = e.categoryWeight(f)

	raw := rs.BaseSeverity + rs.CVSSComponent + rs.Exploitability +
		rs.ClassModifier + rs.ExposureScore + rs.ComplianceScore
	rs.Total = utils.Min(raw*rs.CategoryWeight, 100)
	rs.Total = utils.Round(rs.Total, 2)

	// Enforce a severity floor: GCP SCC's own severity is an authoritative expert signal.
	// Our formula may elevate a finding (via CVSS, exploit data) but must never downgrade
	// it below the band GCP assigned. Real-world CRITICAL/HIGH misconfigurations frequently
	// lack CVE/CVSS metadata and would otherwise score LOW/MEDIUM without this floor.
	floorApplied := false
	switch f.Severity {
	case "CRITICAL":
		if rs.Total < 75 {
			rs.Total = 75.0
			floorApplied = true
		}
	case "HIGH":
		if rs.Total < 55 {
			rs.Total = 55.0
			floorApplied = true
		}
	}

	rs.Rationale = e.buildRationale(f, rs, floorApplied)

	f.RiskScore = rs
	f.Priority = models.PriorityFromScore(rs.Total)
	return rs
}

// ScoreAll scores all findings, using goroutines for parallelism.
func (e *Engine) ScoreAll(findings []*models.Finding) {
	type job struct {
		idx     int
		finding *models.Finding
	}

	jobs := make(chan job, len(findings))
	for i, f := range findings {
		jobs <- job{i, f}
	}
	close(jobs)

	// Use up to 8 workers
	workers := 8
	if len(findings) < workers {
		workers = len(findings)
	}
	if workers == 0 {
		return
	}

	done := make(chan struct{}, workers)
	for w := 0; w < workers; w++ {
		go func() {
			for j := range jobs {
				e.Score(j.finding)
			}
			done <- struct{}{}
		}()
	}
	for w := 0; w < workers; w++ {
		<-done
	}
}

// baseSeverityScore returns the severity component (0-40).
func (e *Engine) baseSeverityScore(f *models.Finding) float64 {
	switch f.Severity {
	case "CRITICAL":
		return e.cfg.CriticalBase
	case "HIGH":
		return e.cfg.HighBase
	case "MEDIUM":
		return e.cfg.MediumBase
	case "LOW":
		return e.cfg.LowBase
	default:
		return e.cfg.LowBase
	}
}

// cvssScore returns the CVSS component scaled to 0-30.
func (e *Engine) cvssScore(f *models.Finding) float64 {
	if f.CVSSScore <= 0 {
		return 0
	}
	score := f.CVSSScore * 3 // scale 0-10 → 0-30
	return utils.Min(score, e.cfg.CVSSMax)
}

// exploitabilityScore returns the exploitability component (0-20).
func (e *Engine) exploitabilityScore(f *models.Finding) float64 {
	var score float64

	if f.ObservedInWild {
		score += 10
	}
	if f.ZeroDay {
		score += 8
	}

	// Exploitation activity
	switch f.ExploitActivity {
	case "HIGH", "ACTIVE":
		score += 6
	case "MEDIUM", "POC":
		score += 4
	case "LOW":
		score += 2
	}

	// Has CVE
	if f.HasCVE() {
		score += 2
	}

	return utils.Min(score, e.cfg.ExploitMax)
}

// classModifierScore returns the finding-class component (0-10).
func (e *Engine) classModifierScore(f *models.Finding) float64 {
	switch f.FindingClass {
	case "THREAT":
		return 10
	case "VULNERABILITY":
		return 7
	case "MISCONFIGURATION":
		return 5
	case "OBSERVATION":
		return 2
	default:
		return 2
	}
}

// highRiskCategories are category substrings that trigger a 1.2x weight.
var highRiskCategories = []string{
	"VULNERABILITY", "PRIVILEGE_ESCALATION", "WEAK_SSL", "PUBLIC", "EXTERNAL",
	"CONTAINER_IMAGE_VULN", "OS_VULNERABILITY",
}

// medRiskCategories trigger 1.0x weight.
var medRiskCategories = []string{
	"AUDIT_LOGGING", "FLOW_LOGS", "BUCKET_LOGGING", "SERVICE_ACCOUNT_KEY",
	"FIREWALL", "IAM", "NETWORK",
}

// exposureScore returns the resource exposure bonus (0-10).
func (e *Engine) exposureScore(f *models.Finding) float64 {
	var score float64

	if f.PublicIPAddress {
		score += 5
	}

	cat := f.Category
	if utils.ContainsAny(cat, "HTTP", "LOAD_BALANCER", "LOADBALANCER", "LB") {
		score += 3
	}
	if utils.ContainsAny(cat, "DATABASE", "DB", "BUCKET", "STORAGE", "GCS", "BIGTABLE", "SPANNER") {
		score += 2
	}

	return utils.Min(score, e.cfg.ExposureMax)
}

// complianceScore returns the compliance impact bonus (0-10).
func (e *Engine) complianceScore(f *models.Finding) float64 {
	var score float64

	if len(f.ComplianceFrameworks) > 0 || f.CompliancesRaw != "" {
		score += 5
	}
	if f.ComplianceDetailsRaw != "" {
		score += 3
	}

	cat := f.Category
	if utils.ContainsAny(cat, "AUDIT", "LOGGING", "MONITORING", "LOG") {
		score += 2
	}

	return utils.Min(score, e.cfg.ComplianceMax)
}

// categoryWeight returns the category risk multiplier (0.8-1.2).
func (e *Engine) categoryWeight(f *models.Finding) float64 {
	cat := strings.ToUpper(f.Category)
	for _, hrc := range highRiskCategories {
		if strings.Contains(cat, hrc) {
			return e.cfg.HighRiskWeight
		}
	}
	for _, mrc := range medRiskCategories {
		if strings.Contains(cat, mrc) {
			return e.cfg.MedRiskWeight
		}
	}
	return e.cfg.LowRiskWeight
}

// buildRationale generates a human-readable explanation for the score.
func (e *Engine) buildRationale(f *models.Finding, rs *models.RiskScore, floorApplied bool) string {
	var parts []string

	parts = append(parts, fmt.Sprintf("%s severity (%.0f pts)", f.Severity, rs.BaseSeverity))

	if rs.CVSSComponent > 0 {
		parts = append(parts, fmt.Sprintf("CVSS %.1f (%.0f pts)", f.CVSSScore, rs.CVSSComponent))
	}
	if f.ObservedInWild {
		parts = append(parts, "exploited in the wild")
	}
	if f.ZeroDay {
		parts = append(parts, "zero-day")
	}
	if f.HasCVE() {
		parts = append(parts, fmt.Sprintf("CVE: %s", f.CVEID))
	}
	if f.PublicIPAddress {
		parts = append(parts, "public IP exposure")
	}
	if len(f.ComplianceFrameworks) > 0 {
		parts = append(parts, fmt.Sprintf("compliance: %s", strings.Join(f.ComplianceFrameworks, ", ")))
	}

	parts = append(parts, fmt.Sprintf("category weight %.1fx", rs.CategoryWeight))
	if floorApplied {
		parts = append(parts, fmt.Sprintf("GCP severity floor applied (%s → %.0f)", f.Severity, rs.Total))
	}
	parts = append(parts, fmt.Sprintf("= %.2f", rs.Total))

	return strings.Join(parts, "; ")
}
