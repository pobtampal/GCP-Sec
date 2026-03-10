package scoring_test

import (
	"testing"

	"github.com/wanaware/GCP-Sec/internal/models"
	"github.com/wanaware/GCP-Sec/pkg/scoring"
)

func scoredFinding(priority string, score float64) *models.Finding {
	return &models.Finding{
		Priority:  priority,
		Category:  "FIREWALL",
		RiskScore: &models.RiskScore{Total: score},
	}
}

func TestFilterByPriority(t *testing.T) {
	findings := []*models.Finding{
		scoredFinding("CRITICAL", 80),
		scoredFinding("HIGH", 60),
		scoredFinding("MEDIUM", 45),
		scoredFinding("LOW", 20),
	}

	got := scoring.FilterByPriority(findings, []string{"CRITICAL", "HIGH"})
	if len(got) != 2 {
		t.Errorf("FilterByPriority len = %d, want 2", len(got))
	}

	// Empty filter returns all
	all := scoring.FilterByPriority(findings, nil)
	if len(all) != 4 {
		t.Errorf("FilterByPriority(nil) len = %d, want 4", len(all))
	}
}

func TestFilterByCategory(t *testing.T) {
	findings := []*models.Finding{
		{Category: "CONTAINER_IMAGE_VULNERABILITY", Priority: "HIGH", RiskScore: &models.RiskScore{Total: 60}},
		{Category: "FLOW_LOGS_DISABLED", Priority: "MEDIUM", RiskScore: &models.RiskScore{Total: 30}},
		{Category: "CONTAINER_IMAGE_VULNERABILITY", Priority: "MEDIUM", RiskScore: &models.RiskScore{Total: 50}},
	}

	got := scoring.FilterByCategory(findings, []string{"CONTAINER_IMAGE_VULNERABILITY"})
	if len(got) != 2 {
		t.Errorf("FilterByCategory len = %d, want 2", len(got))
	}
}

func TestFilterByRiskScore(t *testing.T) {
	findings := []*models.Finding{
		scoredFinding("CRITICAL", 90),
		scoredFinding("HIGH", 60),
		scoredFinding("MEDIUM", 40),
		scoredFinding("LOW", 20),
	}

	got := scoring.FilterByRiskScore(findings, 50, 100)
	if len(got) != 2 {
		t.Errorf("FilterByRiskScore(50, 100) len = %d, want 2", len(got))
	}

	got = scoring.FilterByRiskScore(findings, 0, 100)
	if len(got) != 4 {
		t.Errorf("FilterByRiskScore(0, 100) len = %d, want 4", len(got))
	}
}

func TestSortByRiskScore(t *testing.T) {
	findings := []*models.Finding{
		scoredFinding("LOW", 20),
		scoredFinding("CRITICAL", 90),
		scoredFinding("HIGH", 60),
	}
	scoring.SortByRiskScore(findings)

	if findings[0].RiskScore.Total != 90 {
		t.Errorf("after sort, first score = %.0f, want 90", findings[0].RiskScore.Total)
	}
	if findings[2].RiskScore.Total != 20 {
		t.Errorf("after sort, last score = %.0f, want 20", findings[2].RiskScore.Total)
	}
}

func TestGroupByPriority(t *testing.T) {
	findings := []*models.Finding{
		scoredFinding("CRITICAL", 80),
		scoredFinding("CRITICAL", 85),
		scoredFinding("HIGH", 60),
		scoredFinding("LOW", 20),
	}

	groups := scoring.GroupByPriority(findings)

	if len(groups["CRITICAL"]) != 2 {
		t.Errorf("CRITICAL group len = %d, want 2", len(groups["CRITICAL"]))
	}
	if len(groups["HIGH"]) != 1 {
		t.Errorf("HIGH group len = %d, want 1", len(groups["HIGH"]))
	}
	if len(groups["MEDIUM"]) != 0 {
		t.Errorf("MEDIUM group len = %d, want 0", len(groups["MEDIUM"]))
	}
}

func TestComputeStats(t *testing.T) {
	findings := []*models.Finding{
		scoredFinding("CRITICAL", 100),
		scoredFinding("HIGH", 60),
		scoredFinding("MEDIUM", 40),
		scoredFinding("LOW", 20),
	}

	stats := scoring.ComputeStats(findings)

	if stats.Count != 4 {
		t.Errorf("Count = %d, want 4", stats.Count)
	}
	if stats.Min != 20 {
		t.Errorf("Min = %.0f, want 20", stats.Min)
	}
	if stats.Max != 100 {
		t.Errorf("Max = %.0f, want 100", stats.Max)
	}
	if stats.Mean != 55 {
		t.Errorf("Mean = %.0f, want 55", stats.Mean)
	}

	// Empty
	empty := scoring.ComputeStats([]*models.Finding{})
	if empty.Count != 0 {
		t.Errorf("empty ComputeStats.Count = %d, want 0", empty.Count)
	}
}
