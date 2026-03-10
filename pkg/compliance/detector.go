package compliance

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/wanaware/GCP-Sec/internal/models"
)

// Detector extracts and aggregates compliance violations from findings.
type Detector struct{}

// NewDetector creates a new Detector.
func NewDetector() *Detector { return &Detector{} }

// DetectViolations parses compliance data from a finding and populates
// f.ComplianceFrameworks and f.Violations.
func (d *Detector) DetectViolations(f *models.Finding) {
	violations := d.parseCompliances(f)
	violations = append(violations, d.parseComplianceDetails(f)...)
	f.Violations = dedupViolations(violations)
}

// Aggregate builds a framework → violations map from a slice of findings.
func (d *Detector) Aggregate(findings []*models.Finding) map[string][]*models.ComplianceViolation {
	// framework → control → violation
	index := map[string]map[string]*models.ComplianceViolation{}

	for _, f := range findings {
		for _, v := range f.Violations {
			fw := v.Framework
			if _, ok := index[fw]; !ok {
				index[fw] = map[string]*models.ComplianceViolation{}
			}
			key := fw + ":" + v.Control
			if existing, ok := index[fw][key]; ok {
				existing.Count++
				existing.Findings = append(existing.Findings, f.Name)
			} else {
				cv := &models.ComplianceViolation{
					Framework:   fw,
					Control:     v.Control,
					Description: v.Description,
					Findings:    []string{f.Name},
					Count:       1,
				}
				index[fw][key] = cv
			}
		}
	}

	// Convert to sorted output
	result := map[string][]*models.ComplianceViolation{}
	for fw, controls := range index {
		var list []*models.ComplianceViolation
		for _, v := range controls {
			list = append(list, v)
		}
		sort.Slice(list, func(i, j int) bool {
			return list[i].Count > list[j].Count
		})
		result[fw] = list
	}
	return result
}

// parseCompliances parses the finding.compliances JSON field.
// Expected format: [{"standard": "CIS", "version": "1.2", "ids": ["3.1", "3.2"]}]
func (d *Detector) parseCompliances(f *models.Finding) []models.ComplianceViolation {
	raw := strings.TrimSpace(f.CompliancesRaw)
	if raw == "" || raw == "[]" || raw == "{}" {
		return nil
	}

	type complianceEntry struct {
		Standard string   `json:"standard"`
		Version  string   `json:"version"`
		IDs      []string `json:"ids"`
		// Alternate field names
		Framework string `json:"framework"`
		Name      string `json:"name"`
		Controls  []string `json:"controls"`
	}

	var entries []complianceEntry
	if err := json.Unmarshal([]byte(raw), &entries); err != nil {
		// Try single object
		var single complianceEntry
		if err2 := json.Unmarshal([]byte(raw), &single); err2 == nil {
			entries = []complianceEntry{single}
		} else {
			return nil
		}
	}

	var violations []models.ComplianceViolation
	for _, e := range entries {
		fw := e.Standard
		if fw == "" {
			fw = e.Framework
		}
		if fw == "" {
			fw = e.Name
		}
		fw = CanonicalID(strings.ToUpper(fw))

		ids := e.IDs
		if len(ids) == 0 {
			ids = e.Controls
		}

		if len(ids) == 0 {
			// Record framework-level violation without specific control
			violations = append(violations, models.ComplianceViolation{
				Framework: fw,
				Control:   "N/A",
			})
			continue
		}

		for _, id := range ids {
			violations = append(violations, models.ComplianceViolation{
				Framework:   fw,
				Control:     id,
				Description: fmt.Sprintf("%s control %s", fw, id),
			})
		}
	}
	return violations
}

// parseComplianceDetails parses the finding.compliance_details.frameworks JSON field.
func (d *Detector) parseComplianceDetails(f *models.Finding) []models.ComplianceViolation {
	raw := strings.TrimSpace(f.ComplianceDetailsRaw)
	if raw == "" || raw == "[]" || raw == "{}" {
		return nil
	}

	type framework struct {
		Name     string   `json:"name"`
		Version  string   `json:"version"`
		Controls []string `json:"controls"`
	}

	// Try as array
	var arr []framework
	if err := json.Unmarshal([]byte(raw), &arr); err != nil {
		// Try as object keyed by framework name
		var obj map[string]framework
		if err2 := json.Unmarshal([]byte(raw), &obj); err2 == nil {
			for name, fw := range obj {
				fw.Name = name
				arr = append(arr, fw)
			}
		} else {
			return nil
		}
	}

	var violations []models.ComplianceViolation
	for _, fw := range arr {
		name := CanonicalID(strings.ToUpper(fw.Name))
		for _, ctrl := range fw.Controls {
			violations = append(violations, models.ComplianceViolation{
				Framework:   name,
				Version:     fw.Version,
				Control:     ctrl,
				Description: fmt.Sprintf("%s control %s", name, ctrl),
			})
		}
	}
	return violations
}

// dedupViolations removes duplicate framework+control combinations.
func dedupViolations(vs []models.ComplianceViolation) []models.ComplianceViolation {
	seen := map[string]bool{}
	out := vs[:0:0]
	for _, v := range vs {
		key := v.Framework + "::" + v.Control
		if !seen[key] {
			seen[key] = true
			out = append(out, v)
		}
	}
	return out
}
