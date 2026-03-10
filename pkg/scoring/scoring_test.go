package scoring_test

import (
	"math"
	"testing"

	"github.com/wanaware/GCP-Sec/internal/models"
	"github.com/wanaware/GCP-Sec/pkg/scoring"
)

func approxEq(a, b float64) bool { return math.Abs(a-b) < 1e-9 }

func newEngine() *scoring.Engine {
	return scoring.NewEngine(scoring.DefaultConfig(), nil)
}

// makeF is a convenience constructor for test findings.
func makeF(severity, class, category string) *models.Finding {
	return &models.Finding{
		Severity:    severity,
		FindingClass: class,
		Category:    category,
		State:       "ACTIVE",
	}
}

func TestBaseSeverityScores(t *testing.T) {
	engine := newEngine()
	cfg := scoring.DefaultConfig()

	tests := []struct {
		severity string
		want     float64
	}{
		{"CRITICAL", cfg.CriticalBase},
		{"HIGH", cfg.HighBase},
		{"MEDIUM", cfg.MediumBase},
		{"LOW", cfg.LowBase},
		{"UNKNOWN", cfg.LowBase}, // defaults to LOW
	}

	for _, tc := range tests {
		t.Run(tc.severity, func(t *testing.T) {
			f := makeF(tc.severity, "MISCONFIGURATION", "FIREWALL")
			rs := engine.Score(f)
			if rs.BaseSeverity != tc.want {
				t.Errorf("BaseSeverity(%s) = %.0f, want %.0f", tc.severity, rs.BaseSeverity, tc.want)
			}
		})
	}
}

func TestCVSSComponent(t *testing.T) {
	engine := newEngine()

	tests := []struct {
		cvss float64
		want float64 // cvss * 3, capped at 30
	}{
		{0, 0},
		{5.0, 15},
		{7.5, 22.5},
		{10.0, 30},
		{9.9, 29.7},
	}

	for _, tc := range tests {
		t.Run("", func(t *testing.T) {
			f := makeF("HIGH", "VULNERABILITY", "CONTAINER_IMAGE_VULNERABILITY")
			f.CVSSScore = tc.cvss
			rs := engine.Score(f)
			if !approxEq(rs.CVSSComponent, tc.want) {
				t.Errorf("CVSSComponent(%.1f) = %.4f, want %.4f", tc.cvss, rs.CVSSComponent, tc.want)
			}
		})
	}
}

func TestExploitabilityScore(t *testing.T) {
	engine := newEngine()

	tests := []struct {
		name          string
		inWild        bool
		zeroDay       bool
		exploitActiv  string
		hasCVE        bool
		wantMin       float64
		wantMax       float64
	}{
		{"none", false, false, "", false, 0, 0},
		{"in_wild", true, false, "", false, 10, 10},
		{"zero_day", false, true, "", false, 8, 8},
		{"both+cve", true, true, "", true, 20, 20}, // capped at 20
		{"high_activity", false, false, "HIGH", false, 6, 6},
		{"with_cve", false, false, "", true, 2, 2},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := makeF("HIGH", "VULNERABILITY", "CONTAINER_IMAGE_VULNERABILITY")
			f.ObservedInWild = tc.inWild
			f.ZeroDay = tc.zeroDay
			f.ExploitActivity = tc.exploitActiv
			if tc.hasCVE {
				f.CVEID = "CVE-2021-44228"
			}
			rs := engine.Score(f)
			if rs.Exploitability < tc.wantMin || rs.Exploitability > tc.wantMax {
				t.Errorf("Exploitability = %.0f, want [%.0f, %.0f]",
					rs.Exploitability, tc.wantMin, tc.wantMax)
			}
		})
	}
}

func TestClassModifier(t *testing.T) {
	engine := newEngine()

	tests := []struct {
		class string
		want  float64
	}{
		{"THREAT", 10},
		{"VULNERABILITY", 7},
		{"MISCONFIGURATION", 5},
		{"OBSERVATION", 2},
		{"UNKNOWN", 2},
	}

	for _, tc := range tests {
		t.Run(tc.class, func(t *testing.T) {
			f := makeF("LOW", tc.class, "AUDIT_LOGGING")
			rs := engine.Score(f)
			if rs.ClassModifier != tc.want {
				t.Errorf("ClassModifier(%s) = %.0f, want %.0f", tc.class, rs.ClassModifier, tc.want)
			}
		})
	}
}

func TestExposureScore(t *testing.T) {
	engine := newEngine()

	tests := []struct {
		name      string
		publicIP  bool
		category  string
		wantMin   float64
	}{
		{"none", false, "FIREWALL", 0},
		{"public_ip", true, "FIREWALL", 5},
		{"http_category", false, "HTTP_LOAD_BALANCER", 3},
		{"database", false, "DATABASE_VULNERABILITY", 2},
		{"public+db", true, "DATABASE_VULNERABILITY", 7},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := makeF("MEDIUM", "MISCONFIGURATION", tc.category)
			f.PublicIPAddress = tc.publicIP
			rs := engine.Score(f)
			if rs.ExposureScore < tc.wantMin {
				t.Errorf("ExposureScore(%q, publicIP=%v) = %.0f, want >= %.0f",
					tc.category, tc.publicIP, rs.ExposureScore, tc.wantMin)
			}
		})
	}
}

func TestComplianceScore(t *testing.T) {
	engine := newEngine()

	tests := []struct {
		name            string
		hasFrameworks   bool
		hasDetails      bool
		category        string
		wantMin         float64
	}{
		{"none", false, false, "FIREWALL", 0},
		{"frameworks", true, false, "FIREWALL", 5},
		{"frameworks+details", true, true, "FIREWALL", 8},
		{"audit_category", false, false, "AUDIT_LOGGING_DISABLED", 2},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := makeF("MEDIUM", "MISCONFIGURATION", tc.category)
			if tc.hasFrameworks {
				f.CompliancesRaw = `[{"standard":"CIS"}]`
				f.ComplianceFrameworks = []string{"CIS"}
			}
			if tc.hasDetails {
				f.ComplianceDetailsRaw = `[{"name":"CIS","controls":["3.1"]}]`
			}
			rs := engine.Score(f)
			if rs.ComplianceScore < tc.wantMin {
				t.Errorf("ComplianceScore = %.0f, want >= %.0f", rs.ComplianceScore, tc.wantMin)
			}
		})
	}
}

func TestCategoryWeight(t *testing.T) {
	engine := newEngine()
	cfg := scoring.DefaultConfig()

	tests := []struct {
		category string
		want     float64
	}{
		{"CONTAINER_IMAGE_VULNERABILITY", cfg.HighRiskWeight},
		{"PRIVILEGE_ESCALATION", cfg.HighRiskWeight},
		{"FLOW_LOGS_DISABLED", cfg.MedRiskWeight},
		{"AUDIT_LOGGING_DISABLED", cfg.MedRiskWeight},
		{"SOME_OTHER_FINDING", cfg.LowRiskWeight},
	}

	for _, tc := range tests {
		t.Run(tc.category, func(t *testing.T) {
			f := makeF("LOW", "OBSERVATION", tc.category)
			rs := engine.Score(f)
			if rs.CategoryWeight != tc.want {
				t.Errorf("CategoryWeight(%s) = %.1f, want %.1f",
					tc.category, rs.CategoryWeight, tc.want)
			}
		})
	}
}

func TestScoreCapped100(t *testing.T) {
	engine := newEngine()
	// Max possible raw score: 40 + 30 + 20 + 10 + 10 + 10 = 120, × 1.2 = 144 → capped at 100
	f := makeF("CRITICAL", "THREAT", "CONTAINER_IMAGE_VULNERABILITY")
	f.CVSSScore = 10
	f.ObservedInWild = true
	f.ZeroDay = true
	f.PublicIPAddress = true
	f.CompliancesRaw = `[{"standard":"CIS"}]`
	f.ComplianceFrameworks = []string{"CIS"}
	f.ComplianceDetailsRaw = `[{"name":"CIS"}]`
	f.CVEID = "CVE-2021-44228"

	rs := engine.Score(f)
	if rs.Total > 100 {
		t.Errorf("Score %.2f exceeds 100 cap", rs.Total)
	}
	if rs.Total != 100 {
		t.Logf("Expected 100, got %.2f (acceptable if raw < 144)", rs.Total)
	}
}

func TestPriorityAssignment(t *testing.T) {
	tests := []struct {
		score    float64
		priority string
	}{
		{100, "CRITICAL"},
		{75, "CRITICAL"},
		{74.9, "HIGH"},
		{55, "HIGH"},
		{54.9, "MEDIUM"},
		{35, "MEDIUM"},
		{34.9, "LOW"},
		{0, "LOW"},
	}

	for _, tc := range tests {
		got := models.PriorityFromScore(tc.score)
		if got != tc.priority {
			t.Errorf("PriorityFromScore(%.1f) = %s, want %s", tc.score, got, tc.priority)
		}
	}
}

func TestScoreAll(t *testing.T) {
	engine := newEngine()
	findings := []*models.Finding{
		makeF("HIGH", "VULNERABILITY", "CONTAINER_IMAGE_VULNERABILITY"),
		makeF("MEDIUM", "MISCONFIGURATION", "FLOW_LOGS_DISABLED"),
		makeF("LOW", "OBSERVATION", "SOME_FINDING"),
	}

	engine.ScoreAll(findings)

	for i, f := range findings {
		if f.RiskScore == nil {
			t.Errorf("findings[%d]: RiskScore is nil", i)
			continue
		}
		if f.Priority == "" {
			t.Errorf("findings[%d]: Priority is empty", i)
		}
		if f.RiskScore.Total < 0 || f.RiskScore.Total > 100 {
			t.Errorf("findings[%d]: Score %.2f out of range [0, 100]", i, f.RiskScore.Total)
		}
	}
}

// BenchmarkScore measures scoring throughput.
func BenchmarkScore(b *testing.B) {
	engine := newEngine()
	f := makeF("HIGH", "VULNERABILITY", "CONTAINER_IMAGE_VULNERABILITY")
	f.CVSSScore = 7.5

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		engine.Score(f)
	}
}
