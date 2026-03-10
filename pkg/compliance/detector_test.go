package compliance_test

import (
	"testing"

	"github.com/wanaware/GCP-Sec/internal/models"
	"github.com/wanaware/GCP-Sec/pkg/compliance"
)

func TestDetectViolations_Compliances(t *testing.T) {
	d := compliance.NewDetector()
	f := &models.Finding{
		CompliancesRaw: `[{"standard":"CIS","version":"1.2","ids":["3.1","3.2"]},{"standard":"PCI-DSS","ids":["6.2"]}]`,
	}
	d.DetectViolations(f)

	if len(f.Violations) == 0 {
		t.Fatal("expected violations, got none")
	}

	fwSeen := map[string]bool{}
	for _, v := range f.Violations {
		fwSeen[v.Framework] = true
	}
	if !fwSeen["CIS"] {
		t.Error("expected CIS violations")
	}
	if !fwSeen["PCI-DSS"] {
		t.Error("expected PCI-DSS violations")
	}
}

func TestDetectViolations_ComplianceDetails(t *testing.T) {
	d := compliance.NewDetector()
	f := &models.Finding{
		ComplianceDetailsRaw: `[{"name":"NIST","version":"1.0","controls":["PR.AC-1","PR.DS-5"]}]`,
	}
	d.DetectViolations(f)

	if len(f.Violations) == 0 {
		t.Fatal("expected violations from compliance_details, got none")
	}
	found := false
	for _, v := range f.Violations {
		if v.Framework == "NIST" {
			found = true
		}
	}
	if !found {
		t.Error("expected NIST violations")
	}
}

func TestDetectViolations_Empty(t *testing.T) {
	d := compliance.NewDetector()
	f := &models.Finding{}
	d.DetectViolations(f)
	if len(f.Violations) != 0 {
		t.Errorf("expected no violations for empty finding, got %d", len(f.Violations))
	}
}

func TestAggregate(t *testing.T) {
	d := compliance.NewDetector()
	findings := []*models.Finding{
		{
			Name:           "finding-1",
			CompliancesRaw: `[{"standard":"CIS","ids":["3.1"]}]`,
		},
		{
			Name:           "finding-2",
			CompliancesRaw: `[{"standard":"CIS","ids":["3.1"]}]`,
		},
		{
			Name:           "finding-3",
			CompliancesRaw: `[{"standard":"PCI-DSS","ids":["6.2"]}]`,
		},
	}

	for _, f := range findings {
		d.DetectViolations(f)
	}

	summary := d.Aggregate(findings)

	cisViolations, ok := summary["CIS"]
	if !ok {
		t.Fatal("expected CIS in summary")
	}
	// CIS 3.1 should appear twice
	found := false
	for _, v := range cisViolations {
		if v.Control == "3.1" && v.Count == 2 {
			found = true
		}
	}
	if !found {
		t.Error("expected CIS 3.1 with count=2")
	}

	if _, ok := summary["PCI-DSS"]; !ok {
		t.Error("expected PCI-DSS in summary")
	}
}

func TestCanonicalID(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"CIS", "CIS"},
		{"CIS_GCP", "CIS"},
		{"pci-dss", "PCI-DSS"},
		{"PCIDSS", "PCI-DSS"},
		{"hipaa", "HIPAA"},
		{"UNKNOWN_FRAMEWORK", "UNKNOWN_FRAMEWORK"},
	}
	for _, tc := range tests {
		got := compliance.CanonicalID(tc.input)
		if got != tc.want {
			t.Errorf("CanonicalID(%q) = %q, want %q", tc.input, got, tc.want)
		}
	}
}
