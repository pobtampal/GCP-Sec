package scoring

import (
	"testing"

	"github.com/wanaware/GCP-Sec/internal/models"
)

// helper builds a bare finding with only the specified severity and category set.
func bareFinding(severity, category, findingClass string) *models.Finding {
	return &models.Finding{
		Severity:     severity,
		Category:     category,
		FindingClass: findingClass,
	}
}

func engine() *Engine {
	return NewEngine(DefaultConfig(), nil)
}

// TestSeverityFloor_CriticalNoEnrichment verifies that a GCP CRITICAL finding
// with zero CVE/exploit/compliance data still reaches score ≥75 (CRITICAL priority).
func TestSeverityFloor_CriticalNoEnrichment(t *testing.T) {
	f := bareFinding("CRITICAL", "PUBLIC_BUCKET_ACL", "MISCONFIGURATION")
	rs := engine().Score(f)

	if rs.Total < 75 {
		t.Errorf("CRITICAL severity floor: want score ≥75, got %.2f", rs.Total)
	}
	if f.Priority != models.PriorityCritical {
		t.Errorf("CRITICAL severity floor: want priority CRITICAL, got %s", f.Priority)
	}
}

// TestSeverityFloor_HighNoEnrichment verifies that a GCP HIGH finding with no
// enrichment data reaches score ≥55 (HIGH priority).
func TestSeverityFloor_HighNoEnrichment(t *testing.T) {
	f := bareFinding("HIGH", "ADMIN_SERVICE_ACCOUNT", "MISCONFIGURATION")
	rs := engine().Score(f)

	if rs.Total < 55 {
		t.Errorf("HIGH severity floor: want score ≥55, got %.2f", rs.Total)
	}
	if f.Priority != models.PriorityHigh {
		t.Errorf("HIGH severity floor: want priority HIGH, got %s", f.Priority)
	}
}

// TestSeverityFloor_MediumNoFloor verifies that MEDIUM severity is NOT floored —
// it can fall to LOW based on computed score.
func TestSeverityFloor_MediumNoFloor(t *testing.T) {
	f := bareFinding("MEDIUM", "SOME_OBSCURE_CATEGORY", "MISCONFIGURATION")
	rs := engine().Score(f)

	// MEDIUM base=20, class=5, weight=0.8 → 25×0.8=20 → LOW
	// The test just confirms no artificial floor lifts MEDIUM.
	if rs.Total >= 55 {
		t.Errorf("MEDIUM should not be floored to HIGH/CRITICAL, got %.2f", rs.Total)
	}
}

// TestSeverityFloor_CriticalWithCVSS verifies that CRITICAL + rich CVSS data
// can still score 100 (the ceiling, not capped by floor).
func TestSeverityFloor_CriticalWithCVSS(t *testing.T) {
	f := bareFinding("CRITICAL", "CONTAINER_IMAGE_VULNERABILITY", "VULNERABILITY")
	f.CVSSScore = 10.0
	f.ObservedInWild = true
	f.CVEID = "CVE-2021-44228"

	rs := engine().Score(f)

	if rs.Total < 75 {
		t.Errorf("CRITICAL+CVSS10 floor: want score ≥75, got %.2f", rs.Total)
	}
	if f.Priority != models.PriorityCritical {
		t.Errorf("CRITICAL+CVSS10 floor: want priority CRITICAL, got %s", f.Priority)
	}
}

// TestSeverityFloor_HighWithCVSS verifies HIGH + CVSS can push above 55 naturally.
func TestSeverityFloor_HighWithCVSS(t *testing.T) {
	f := bareFinding("HIGH", "CONTAINER_IMAGE_VULNERABILITY", "VULNERABILITY")
	f.CVSSScore = 8.8
	f.CVEID = "CVE-2023-22462"

	rs := engine().Score(f)

	if rs.Total < 55 {
		t.Errorf("HIGH+CVSS8.8: want score ≥55, got %.2f", rs.Total)
	}
}

// TestSeverityFloor_RationaleContainsFloorNote verifies that the rationale text
// mentions the floor when it was applied.
func TestSeverityFloor_RationaleContainsFloorNote(t *testing.T) {
	f := bareFinding("CRITICAL", "SOME_UNKNOWN_CATEGORY", "MISCONFIGURATION")
	engine().Score(f)

	if f.RiskScore == nil {
		t.Fatal("RiskScore is nil")
	}
	rationale := f.RiskScore.Rationale
	wantSubstr := "GCP severity floor applied"
	if !contains(rationale, wantSubstr) {
		t.Errorf("rationale should contain %q when floor is applied, got: %s", wantSubstr, rationale)
	}
}

// TestSeverityFloor_RationaleNoFloorNote verifies that when no floor is needed
// (score already above threshold), the rationale does NOT mention the floor.
func TestSeverityFloor_RationaleNoFloorNote(t *testing.T) {
	f := bareFinding("CRITICAL", "CONTAINER_IMAGE_VULNERABILITY", "VULNERABILITY")
	f.CVSSScore = 10.0
	f.ObservedInWild = true
	f.CVEID = "CVE-2021-44228"
	engine().Score(f)

	if f.RiskScore == nil {
		t.Fatal("RiskScore is nil")
	}
	// Score should be 100 (ceiling), floor was not needed.
	if contains(f.RiskScore.Rationale, "floor applied") {
		t.Errorf("rationale should NOT mention floor when score exceeds threshold naturally")
	}
}

func contains(s, sub string) bool {
	return len(s) >= len(sub) && (s == sub || len(s) > 0 && containsStr(s, sub))
}

func containsStr(s, sub string) bool {
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
