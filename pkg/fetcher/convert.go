// Package fetcher retrieves findings from the GCP Security Command Center API.
package fetcher

import (
	"encoding/json"
	"strings"
	"time"

	"cloud.google.com/go/securitycenter/apiv1/securitycenterpb"

	"github.com/wanaware/GCP-Sec/internal/models"
)

// ConvertFinding converts a GCP SCC protobuf ListFindingsResult
// into the internal *models.Finding type.
func ConvertFinding(result *securitycenterpb.ListFindingsResponse_ListFindingsResult) *models.Finding {
	pb := result.GetFinding()
	res := result.GetResource()

	f := &models.Finding{}

	// Core identification
	f.Name = pb.GetName()
	f.FindingClass = sanitizeEnum(pb.GetFindingClass().String())
	f.Category = strings.ToUpper(pb.GetCategory())
	f.State = sanitizeEnum(pb.GetState().String())
	f.Severity = sanitizeSeverity(pb.GetSeverity().String())

	// Resource information
	if res != nil {
		f.ResourceName = res.GetName()
		f.ResourceDisplayName = res.GetDisplayName()
		f.ResourceType = res.GetType()
		f.ProjectID = extractProjectID(res.GetProjectName())
		f.ProjectDisplayName = res.GetProjectDisplayName()
	}

	// Timestamps
	if et := pb.GetEventTime(); et != nil && et.IsValid() {
		f.EventTime = et.AsTime()
		f.EventTimeRaw = f.EventTime.Format(time.RFC3339)
	}
	if ct := pb.GetCreateTime(); ct != nil && ct.IsValid() {
		f.CreateTime = ct.AsTime()
		f.CreateTimeRaw = f.CreateTime.Format(time.RFC3339)
	}

	// Description and remediation hints
	f.Description = pb.GetDescription()
	f.ExternalURI = pb.GetExternalUri()
	f.NextSteps = pb.GetNextSteps()

	// Vulnerability data
	if vuln := pb.GetVulnerability(); vuln != nil {
		if cve := vuln.GetCve(); cve != nil {
			f.CVEID = strings.ToUpper(cve.GetId())
			f.ObservedInWild = cve.GetObservedInTheWild()
			f.ZeroDay = cve.GetZeroDay()
			f.ExploitActivity = sanitizeExploitActivity(cve.GetExploitationActivity().String())

			if cvss := cve.GetCvssv3(); cvss != nil {
				f.CVSSScore = cvss.GetBaseScore()
			}
		}
	}

	// Compliance data
	compliances := pb.GetCompliances()
	if len(compliances) > 0 {
		f.ComplianceFrameworks = extractFrameworks(compliances)
		f.CompliancesRaw = serializeCompliances(compliances)
	}

	return f
}

// sanitizeEnum converts protobuf enum string values to clean uppercase
// names by stripping known prefixes (e.g. "FINDING_CLASS_VULNERABILITY" → "VULNERABILITY").
func sanitizeEnum(s string) string {
	s = strings.ToUpper(s)
	for _, prefix := range []string{
		"FINDING_CLASS_",
		"STATE_",
		"SEVERITY_",
		"EXPLOITATION_ACTIVITY_",
		"MUTE_",
	} {
		s = strings.TrimPrefix(s, prefix)
	}
	if s == "UNSPECIFIED" || s == "" {
		return ""
	}
	return s
}

// sanitizeSeverity handles the severity enum, defaulting to "LOW"
// when the value is unspecified (matching the CSV parser behavior).
func sanitizeSeverity(s string) string {
	s = sanitizeEnum(s)
	if s == "" {
		return "LOW"
	}
	return s
}

// sanitizeExploitActivity maps GCP SCC exploitation activity enum values
// to the activity strings used by the scoring engine.
func sanitizeExploitActivity(s string) string {
	s = sanitizeEnum(s)
	switch s {
	case "WIDE", "CONFIRMED":
		return "ACTIVE"
	case "AVAILABLE":
		return "POC"
	case "ANTICIPATED":
		return "LOW"
	case "NO_KNOWN", "":
		return ""
	default:
		return strings.ToUpper(s)
	}
}

// extractProjectID extracts the project ID from a full project resource name.
// Input: "projects/my-project" or "organizations/123/projects/my-project"
// Output: "my-project"
func extractProjectID(projectName string) string {
	if projectName == "" {
		return ""
	}
	parts := strings.Split(projectName, "/")
	for i, p := range parts {
		if p == "projects" && i+1 < len(parts) {
			return parts[i+1]
		}
	}
	return projectName
}

// extractFrameworks collects unique framework names from compliances.
func extractFrameworks(cs []*securitycenterpb.Compliance) []string {
	seen := make(map[string]struct{})
	var out []string
	for _, c := range cs {
		name := strings.ToUpper(c.GetStandard())
		if name == "" {
			continue
		}
		if _, ok := seen[name]; !ok {
			seen[name] = struct{}{}
			out = append(out, name)
		}
	}
	return out
}

// complianceJSON is the JSON format expected by the compliance detector.
type complianceJSON struct {
	Standard string   `json:"standard"`
	Version  string   `json:"version,omitempty"`
	IDs      []string `json:"ids,omitempty"`
}

// serializeCompliances produces JSON matching the format expected by
// the compliance.Detector: [{"standard":"CIS","version":"1.2","ids":["3.1"]}]
func serializeCompliances(cs []*securitycenterpb.Compliance) string {
	var items []complianceJSON
	for _, c := range cs {
		items = append(items, complianceJSON{
			Standard: c.GetStandard(),
			Version:  c.GetVersion(),
			IDs:      c.GetIds(),
		})
	}
	data, err := json.Marshal(items)
	if err != nil {
		return ""
	}
	return string(data)
}
