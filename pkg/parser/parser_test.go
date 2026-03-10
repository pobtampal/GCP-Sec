package parser_test

import (
	"strings"
	"testing"

	"github.com/wanaware/GCP-Sec/pkg/parser"
)

const sampleCSV = `name,finding_class,category,state,severity,resource_name,resource_display_name,project_id,project_display_name,description,finding.next_steps,finding.vulnerability.cve.id,finding.vulnerability.cve.cvssv3,finding.vulnerability.cve.observed_in_the_wild,finding.vulnerability.cve.zero_day,finding.external_exposure.public_ip_address,finding.compliances
organizations/123/sources/456/findings/abc,VULNERABILITY,CONTAINER_IMAGE_VULNERABILITY,ACTIVE,HIGH,//container.googleapis.com/projects/my-project/zones/us-central1-a/clusters/my-cluster,my-cluster,my-project,My Project,A high severity vulnerability was found.,Update the container image.,CVE-2021-44228,{"base_score": 10.0},true,false,false,"[{""standard"":""CIS"",""version"":""1.2"",""ids"":[""5.1""]}]"
organizations/123/sources/456/findings/def,MISCONFIGURATION,FLOW_LOGS_DISABLED,ACTIVE,MEDIUM,//compute.googleapis.com/projects/my-project/regions/us-central1/subnetworks/default,default,my-project,My Project,VPC Flow Logs are disabled.,Enable flow logs.,,,,,false,
organizations/123/sources/456/findings/ghi,OBSERVATION,SOME_FINDING,ACTIVE,LOW,//compute.googleapis.com/projects/my-project/global/firewalls/fw-rule,fw-rule,my-project,My Project,Observation note.,Review firewall.,,,,,false,
`

func TestParse(t *testing.T) {
	p := parser.NewParser(nil)
	findings, errs, err := p.Parse(strings.NewReader(sampleCSV))
	if err != nil {
		t.Fatalf("Parse() error: %v", err)
	}
	if errs != 0 {
		t.Errorf("unexpected parse errors: %d", errs)
	}
	if len(findings) != 3 {
		t.Fatalf("len(findings) = %d, want 3", len(findings))
	}

	// First finding
	f := findings[0]
	if f.Severity != "HIGH" {
		t.Errorf("findings[0].Severity = %q, want HIGH", f.Severity)
	}
	if f.FindingClass != "VULNERABILITY" {
		t.Errorf("findings[0].FindingClass = %q, want VULNERABILITY", f.FindingClass)
	}
	if f.CVSSScore != 10.0 {
		t.Errorf("findings[0].CVSSScore = %.1f, want 10.0", f.CVSSScore)
	}
	if !f.ObservedInWild {
		t.Errorf("findings[0].ObservedInWild should be true")
	}
	if f.CVEID != "CVE-2021-44228" {
		t.Errorf("findings[0].CVEID = %q, want CVE-2021-44228", f.CVEID)
	}
	if len(f.ComplianceFrameworks) == 0 {
		t.Errorf("findings[0].ComplianceFrameworks should not be empty")
	}
}

func TestParseMissingSeverity(t *testing.T) {
	csv := `name,category,state,severity,finding_class
test-finding,FIREWALL,ACTIVE,,MISCONFIGURATION
`
	p := parser.NewParser(nil)
	findings, _, err := p.Parse(strings.NewReader(csv))
	if err != nil {
		t.Fatalf("Parse() error: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].Severity != "LOW" {
		t.Errorf("missing severity should default to LOW, got %q", findings[0].Severity)
	}
}

func TestParseCVSSFormats(t *testing.T) {
	tests := []struct {
		name  string
		raw   string
		want  float64
	}{
		{"json_base_score", `{"base_score": 7.5}`, 7.5},
		{"plain_number", "9.8", 9.8},
		{"empty", "", 0},
		{"invalid", "not-a-number", 0},
	}

	csvTemplate := `name,finding_class,category,state,severity,finding.vulnerability.cve.cvssv3
finding-1,VULNERABILITY,TEST,ACTIVE,HIGH,CVSS_PLACEHOLDER
`

	p := parser.NewParser(nil)
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			csvData := strings.ReplaceAll(csvTemplate, "CVSS_PLACEHOLDER", tc.raw)
			findings, _, err := p.Parse(strings.NewReader(csvData))
			if err != nil {
				t.Fatalf("Parse() error: %v", err)
			}
			if len(findings) != 1 {
				t.Fatalf("expected 1 finding, got %d", len(findings))
			}
			if findings[0].CVSSScore != tc.want {
				t.Errorf("CVSSScore(%q) = %.1f, want %.1f", tc.raw, findings[0].CVSSScore, tc.want)
			}
		})
	}
}

func TestParseMalformedRows(t *testing.T) {
	// CSV with a row that has too few fields (lazy CSV reader handles this gracefully)
	csv := `name,finding_class,category,state,severity
finding-1,VULNERABILITY,TEST,ACTIVE,HIGH
finding-2
finding-3,MISCONFIGURATION,OTHER,ACTIVE,LOW
`
	p := parser.NewParser(nil)
	findings, _, err := p.Parse(strings.NewReader(csv))
	if err != nil {
		t.Fatalf("Parse() error: %v", err)
	}
	// Should have parsed at least the valid rows
	if len(findings) == 0 {
		t.Error("expected at least some findings to be parsed")
	}
}

func TestParseComplianceFrameworks(t *testing.T) {
	csv := `name,finding_class,category,state,severity,finding.compliances
f1,MISCONFIGURATION,TEST,ACTIVE,MEDIUM,"[{""standard"":""CIS"",""version"":""1.2"",""ids"":[""3.1"",""3.2""]}]"
f2,MISCONFIGURATION,TEST,ACTIVE,MEDIUM,"[{""standard"":""PCI-DSS""},{""standard"":""HIPAA""}]"
f3,MISCONFIGURATION,TEST,ACTIVE,MEDIUM,
`
	p := parser.NewParser(nil)
	findings, _, err := p.Parse(strings.NewReader(csv))
	if err != nil {
		t.Fatalf("Parse() error: %v", err)
	}
	if len(findings) != 3 {
		t.Fatalf("expected 3 findings, got %d", len(findings))
	}

	if len(findings[0].ComplianceFrameworks) == 0 {
		t.Error("findings[0] should have compliance frameworks")
	}
	if len(findings[1].ComplianceFrameworks) < 2 {
		t.Errorf("findings[1] should have 2 compliance frameworks, got %d", len(findings[1].ComplianceFrameworks))
	}
	if len(findings[2].ComplianceFrameworks) != 0 {
		t.Errorf("findings[2] should have no compliance frameworks, got %v", findings[2].ComplianceFrameworks)
	}
}

// TestParseGCPSCCExportFormat verifies that CSV data using the dotted column
// names produced by "gcloud scc findings list --format=csv" parses correctly.
func TestParseGCPSCCExportFormat(t *testing.T) {
	const gcloudCSV = `finding.name,finding.findingClass,finding.category,finding.state,finding.severity,resource.name,resource.displayName,resource.projectId,resource.projectDisplayName,finding.description,finding.next_steps,finding.vulnerability.cve.id,finding.vulnerability.cve.cvssv3,finding.vulnerability.cve.observed_in_the_wild,finding.vulnerability.cve.zero_day,finding.external_exposure.public_ip_address,finding.compliances
organizations/123/sources/456/findings/abc,VULNERABILITY,CONTAINER_IMAGE_VULNERABILITY,ACTIVE,CRITICAL,//container.googleapis.com/projects/my-project/zones/us-central1-a/clusters/my-cluster,my-cluster,my-project,My Project,A critical vulnerability was found.,Update the container image.,CVE-2021-44228,{"base_score": 10.0},true,false,false,"[{""standard"":""CIS"",""version"":""1.2"",""ids"":[""5.1""]}]"
organizations/123/sources/456/findings/def,MISCONFIGURATION,FLOW_LOGS_DISABLED,ACTIVE,HIGH,//compute.googleapis.com/projects/my-project/regions/us-central1/subnetworks/default,default,my-project,My Project,VPC Flow Logs are disabled.,Enable flow logs.,,,,,false,
`

	p := parser.NewParser(nil)
	findings, errs, err := p.Parse(strings.NewReader(gcloudCSV))
	if err != nil {
		t.Fatalf("Parse() error: %v", err)
	}
	if errs != 0 {
		t.Errorf("unexpected parse errors: %d", errs)
	}
	if len(findings) != 2 {
		t.Fatalf("len(findings) = %d, want 2", len(findings))
	}

	f := findings[0]
	if f.Name != "organizations/123/sources/456/findings/abc" {
		t.Errorf("Name = %q, want organizations/123/sources/456/findings/abc", f.Name)
	}
	if f.FindingClass != "VULNERABILITY" {
		t.Errorf("FindingClass = %q, want VULNERABILITY", f.FindingClass)
	}
	if f.Category != "CONTAINER_IMAGE_VULNERABILITY" {
		t.Errorf("Category = %q, want CONTAINER_IMAGE_VULNERABILITY", f.Category)
	}
	if f.State != "ACTIVE" {
		t.Errorf("State = %q, want ACTIVE", f.State)
	}
	if f.Severity != "CRITICAL" {
		t.Errorf("Severity = %q, want CRITICAL", f.Severity)
	}
	if f.ResourceName != "//container.googleapis.com/projects/my-project/zones/us-central1-a/clusters/my-cluster" {
		t.Errorf("ResourceName = %q, unexpected", f.ResourceName)
	}
	if f.ResourceDisplayName != "my-cluster" {
		t.Errorf("ResourceDisplayName = %q, want my-cluster", f.ResourceDisplayName)
	}
	if f.ProjectID != "my-project" {
		t.Errorf("ProjectID = %q, want my-project", f.ProjectID)
	}
	if f.CVSSScore != 10.0 {
		t.Errorf("CVSSScore = %.1f, want 10.0", f.CVSSScore)
	}
	if f.CVEID != "CVE-2021-44228" {
		t.Errorf("CVEID = %q, want CVE-2021-44228", f.CVEID)
	}

	f2 := findings[1]
	if f2.Severity != "HIGH" {
		t.Errorf("findings[1].Severity = %q, want HIGH", f2.Severity)
	}
}

// TestParseOriginalFormatStillWorks ensures the existing sample CSV format
// (bare column names) continues to parse correctly after the alias change.
func TestParseOriginalFormatStillWorks(t *testing.T) {
	p := parser.NewParser(nil)
	findings, errs, err := p.Parse(strings.NewReader(sampleCSV))
	if err != nil {
		t.Fatalf("Parse() error: %v", err)
	}
	if errs != 0 {
		t.Errorf("unexpected parse errors: %d", errs)
	}
	if len(findings) != 3 {
		t.Fatalf("len(findings) = %d, want 3", len(findings))
	}
	if findings[0].Severity != "HIGH" {
		t.Errorf("findings[0].Severity = %q, want HIGH", findings[0].Severity)
	}
	if findings[0].FindingClass != "VULNERABILITY" {
		t.Errorf("findings[0].FindingClass = %q, want VULNERABILITY", findings[0].FindingClass)
	}
}

// TestParseMixedColumnNames verifies that a CSV with both bare and dotted
// column names resolves correctly (bare names take precedence).
func TestParseMixedColumnNames(t *testing.T) {
	const mixedCSV = `name,severity,finding.severity,category,state,finding_class
test-finding,HIGH,LOW,FIREWALL,ACTIVE,MISCONFIGURATION
`
	p := parser.NewParser(nil)
	findings, _, err := p.Parse(strings.NewReader(mixedCSV))
	if err != nil {
		t.Fatalf("Parse() error: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].Severity != "HIGH" {
		t.Errorf("Severity = %q, want HIGH (bare column should take precedence)", findings[0].Severity)
	}
}

// TestParseCamelCaseColumns verifies camelCase GCP API column names work.
func TestParseCamelCaseColumns(t *testing.T) {
	const camelCSV = `finding.name,finding.findingClass,finding.category,finding.state,finding.severity,resource.name,resource.projectId
organizations/123/sources/456/findings/xyz,THREAT,ADMIN_SERVICE_ACCOUNT,ACTIVE,CRITICAL,//iam.googleapis.com/projects/prod/serviceAccounts/sa@prod.iam.gserviceaccount.com,prod
`
	p := parser.NewParser(nil)
	findings, _, err := p.Parse(strings.NewReader(camelCSV))
	if err != nil {
		t.Fatalf("Parse() error: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	f := findings[0]
	if f.FindingClass != "THREAT" {
		t.Errorf("FindingClass = %q, want THREAT", f.FindingClass)
	}
	if f.Severity != "CRITICAL" {
		t.Errorf("Severity = %q, want CRITICAL", f.Severity)
	}
	if f.ProjectID != "prod" {
		t.Errorf("ProjectID = %q, want prod", f.ProjectID)
	}
}
