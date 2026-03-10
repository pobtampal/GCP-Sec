package scoring

import (
	"sort"

	"github.com/wanaware/GCP-Sec/internal/models"
	"github.com/wanaware/GCP-Sec/internal/utils"
)

// FilterByPriority returns findings whose priority is in the allowed set.
// priorities should be upper-cased (e.g., "HIGH", "CRITICAL").
func FilterByPriority(findings []*models.Finding, priorities []string) []*models.Finding {
	if len(priorities) == 0 {
		return findings
	}
	allowed := make(map[string]bool, len(priorities))
	for _, p := range priorities {
		allowed[utils.NormalizeString(p)] = true
	}
	out := findings[:0:0]
	for _, f := range findings {
		if allowed[f.Priority] {
			out = append(out, f)
		}
	}
	return out
}

// FilterByCategory returns findings whose category is in the allowed set.
func FilterByCategory(findings []*models.Finding, categories []string) []*models.Finding {
	if len(categories) == 0 {
		return findings
	}
	allowed := make(map[string]bool, len(categories))
	for _, c := range categories {
		allowed[utils.NormalizeString(c)] = true
	}
	out := findings[:0:0]
	for _, f := range findings {
		if allowed[f.Category] {
			out = append(out, f)
		}
	}
	return out
}

// FilterByProject returns findings from the given GCP projects.
func FilterByProject(findings []*models.Finding, projects []string) []*models.Finding {
	if len(projects) == 0 {
		return findings
	}
	allowed := make(map[string]bool, len(projects))
	for _, p := range projects {
		allowed[utils.NormalizeString(p)] = true
	}
	out := findings[:0:0]
	for _, f := range findings {
		if allowed[f.ProjectID] || allowed[f.ProjectDisplayName] {
			out = append(out, f)
		}
	}
	return out
}

// FilterByRiskScore returns findings whose risk score is within [min, max].
func FilterByRiskScore(findings []*models.Finding, min, max float64) []*models.Finding {
	out := findings[:0:0]
	for _, f := range findings {
		if f.RiskScore == nil {
			continue
		}
		if f.RiskScore.Total >= min && f.RiskScore.Total <= max {
			out = append(out, f)
		}
	}
	return out
}

// SortByRiskScore sorts findings in descending order of risk score.
func SortByRiskScore(findings []*models.Finding) {
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
}

// GroupByPriority separates findings into priority buckets.
func GroupByPriority(findings []*models.Finding) map[string][]*models.Finding {
	groups := map[string][]*models.Finding{
		models.PriorityCritical: {},
		models.PriorityHigh:     {},
		models.PriorityMedium:   {},
		models.PriorityLow:      {},
	}
	for _, f := range findings {
		p := f.Priority
		if p == "" {
			p = models.PriorityLow
		}
		groups[p] = append(groups[p], f)
	}
	return groups
}

// ComputeStats computes risk score statistics for a set of findings.
func ComputeStats(findings []*models.Finding) models.RiskScoreStats {
	scores := make([]float64, 0, len(findings))
	for _, f := range findings {
		if f.RiskScore != nil {
			scores = append(scores, f.RiskScore.Total)
		}
	}
	if len(scores) == 0 {
		return models.RiskScoreStats{}
	}
	sort.Float64s(scores)
	return models.RiskScoreStats{
		Count:  len(scores),
		Mean:   utils.Round(utils.Mean(scores), 2),
		Median: utils.Round(utils.Median(scores), 2),
		Min:    scores[0],
		Max:    scores[len(scores)-1],
		StdDev: utils.Round(utils.StdDev(scores), 2),
	}
}
