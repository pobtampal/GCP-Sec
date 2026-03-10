package remediation_test

import (
	"strings"
	"testing"
	"time"

	"github.com/wanaware/GCP-Sec/internal/models"
	"github.com/wanaware/GCP-Sec/pkg/remediation"
)

// ── parseResourceName tests ──────────────────────────────────────────────────

func TestParseResourceName_Subnet(t *testing.T) {
	// Exported via the package-level helper we test indirectly via scripts.
	// We drive it through ScriptGenerator to avoid exporting a private function.
	sg := remediation.NewScriptGenerator()
	f := criticalFinding("FLOW_LOGS_DISABLED",
		"//compute.googleapis.com/projects/my-proj/regions/us-east1/subnetworks/my-subnet",
		"my-proj")
	script, lang := sg.Generate(f)

	if lang != "bash" {
		t.Errorf("lang = %q, want bash", lang)
	}
	for _, want := range []string{"my-proj", "us-east1", "my-subnet"} {
		if !strings.Contains(script, want) {
			t.Errorf("script should contain %q", want)
		}
	}
}

func TestParseResourceName_Cluster(t *testing.T) {
	sg := remediation.NewScriptGenerator()
	f := criticalFinding("CONTAINER_IMAGE_VULNERABILITY",
		"//container.googleapis.com/projects/prod-proj/zones/us-central1-a/clusters/prod-cluster/k8s/namespaces/default/pods/api-server",
		"prod-proj")
	f.ResourceDisplayName = "api-server"
	script, lang := sg.Generate(f)

	if lang != "python3" {
		t.Errorf("lang = %q, want python3", lang)
	}
	for _, want := range []string{"prod-proj", "prod-cluster", "us-central1-a"} {
		if !strings.Contains(script, want) {
			t.Errorf("script should contain %q", want)
		}
	}
}

func TestParseResourceName_Firewall_Global(t *testing.T) {
	sg := remediation.NewScriptGenerator()
	f := criticalFinding("OPEN_FIREWALL_TO_PUBLIC",
		"//compute.googleapis.com/projects/my-proj/global/firewalls/allow-ssh-all",
		"my-proj")
	script, lang := sg.Generate(f)

	if lang != "bash" {
		t.Errorf("lang = %q, want bash", lang)
	}
	if !strings.Contains(script, "allow-ssh-all") {
		t.Errorf("script should contain firewall rule name")
	}
}

func TestParseResourceName_ServiceAccountKey(t *testing.T) {
	sg := remediation.NewScriptGenerator()
	f := criticalFinding("SERVICE_ACCOUNT_KEY_NOT_ROTATED",
		"//iam.googleapis.com/projects/my-proj/serviceAccounts/sa@my-proj.iam.gserviceaccount.com/keys/abcdef1234",
		"my-proj")
	script, lang := sg.Generate(f)

	if lang != "bash" {
		t.Errorf("lang = %q, want bash", lang)
	}
	if !strings.Contains(script, "sa@my-proj.iam.gserviceaccount.com") {
		t.Errorf("script should contain service account email")
	}
	if !strings.Contains(script, "abcdef1234") {
		t.Errorf("script should contain key ID")
	}
}

// ── Language selection tests ─────────────────────────────────────────────────

func TestScriptGenerator_BashCategories(t *testing.T) {
	bashCats := []string{
		"FLOW_LOGS_DISABLED",
		"PRIVATE_GOOGLE_ACCESS_DISABLED",
		"BUCKET_LOGGING_DISABLED",
		"AUDIT_LOGGING_DISABLED",
		"FIREWALL_RULE_LOGGING_DISABLED",
		"OPEN_FIREWALL_TO_PUBLIC",
		"WEAK_SSL_POLICY",
		"SERVICE_ACCOUNT_KEY_NOT_ROTATED",
		"ANOMALOUS_IAM_GRANT",
	}
	sg := remediation.NewScriptGenerator()
	for _, cat := range bashCats {
		f := criticalFinding(cat, "", "proj")
		_, lang := sg.Generate(f)
		if lang != "bash" {
			t.Errorf("category %s: lang = %q, want bash", cat, lang)
		}
	}
}

func TestScriptGenerator_PythonCategories(t *testing.T) {
	pythonCats := []string{
		"CONTAINER_IMAGE_VULNERABILITY",
		"OS_VULNERABILITY",
	}
	sg := remediation.NewScriptGenerator()
	for _, cat := range pythonCats {
		f := criticalFinding(cat, "", "proj")
		_, lang := sg.Generate(f)
		if lang != "python3" {
			t.Errorf("category %s: lang = %q, want python3", cat, lang)
		}
	}
}

func TestScriptGenerator_DefaultCategory(t *testing.T) {
	sg := remediation.NewScriptGenerator()
	f := criticalFinding("UNKNOWN_FINDING_TYPE", "", "my-proj")
	script, lang := sg.Generate(f)

	if lang != "bash" {
		t.Errorf("default lang = %q, want bash", lang)
	}
	if !strings.Contains(script, "gcloud asset search-all-resources") {
		t.Errorf("default script should contain gcloud asset search-all-resources")
	}
}

// ── Script content tests ─────────────────────────────────────────────────────

func TestScriptGenerator_Shebangs(t *testing.T) {
	sg := remediation.NewScriptGenerator()

	bashF := criticalFinding("FLOW_LOGS_DISABLED", "", "proj")
	bashScript, _ := sg.Generate(bashF)
	if !strings.HasPrefix(bashScript, "#!/usr/bin/env bash") {
		t.Errorf("bash script should start with #!/usr/bin/env bash")
	}

	pyF := criticalFinding("CONTAINER_IMAGE_VULNERABILITY", "", "proj")
	pyScript, _ := sg.Generate(pyF)
	if !strings.HasPrefix(pyScript, "#!/usr/bin/env python3") {
		t.Errorf("python3 script should start with #!/usr/bin/env python3")
	}
}

func TestScriptGenerator_DryRunPresentInAllBash(t *testing.T) {
	bashCats := []string{
		"FLOW_LOGS_DISABLED",
		"PRIVATE_GOOGLE_ACCESS_DISABLED",
		"BUCKET_LOGGING_DISABLED",
		"AUDIT_LOGGING_DISABLED",
		"FIREWALL_RULE_LOGGING_DISABLED",
		"OPEN_FIREWALL_TO_PUBLIC",
		"WEAK_SSL_POLICY",
		"SERVICE_ACCOUNT_KEY_NOT_ROTATED",
		"ANOMALOUS_IAM_GRANT",
	}
	sg := remediation.NewScriptGenerator()
	for _, cat := range bashCats {
		f := criticalFinding(cat, "", "proj")
		script, _ := sg.Generate(f)
		if !strings.Contains(script, "DRY_RUN") {
			t.Errorf("category %s: bash script should contain DRY_RUN guard", cat)
		}
	}
}

func TestScriptGenerator_HeaderContainsFindingName(t *testing.T) {
	sg := remediation.NewScriptGenerator()
	f := criticalFinding("FLOW_LOGS_DISABLED", "", "my-project")
	f.Name = "organizations/123/sources/456/findings/test-finding-001"
	script, _ := sg.Generate(f)

	if !strings.Contains(script, "test-finding-001") {
		t.Errorf("script header should contain the finding short name")
	}
}

func TestScriptGenerator_CVEInHeader(t *testing.T) {
	sg := remediation.NewScriptGenerator()
	f := criticalFinding("CONTAINER_IMAGE_VULNERABILITY", "", "proj")
	f.CVEID = "CVE-2021-44228"
	f.CVSSScore = 10.0
	script, _ := sg.Generate(f)

	if !strings.Contains(script, "CVE-2021-44228") {
		t.Errorf("script should contain CVE ID in header")
	}
}

// ── Integration with guidance.Generate ──────────────────────────────────────

func TestGenerate_CriticalFindingGetsScript(t *testing.T) {
	gen := remediation.NewGenerator()
	f := criticalFinding("FLOW_LOGS_DISABLED", "", "my-proj")
	gen.Generate(f)

	if f.Remediation == nil {
		t.Fatal("Remediation should not be nil")
	}
	if f.Remediation.RemediationScript == "" {
		t.Error("CRITICAL finding should have a non-empty RemediationScript")
	}
	if f.Remediation.RemediationScriptLang != "bash" {
		t.Errorf("RemediationScriptLang = %q, want bash", f.Remediation.RemediationScriptLang)
	}
}

func TestGenerate_HighFindingGetsNoScript(t *testing.T) {
	gen := remediation.NewGenerator()
	f := &models.Finding{
		Category:   "FLOW_LOGS_DISABLED",
		Priority:   models.PriorityHigh,
		ProjectID:  "my-proj",
		Severity:   "HIGH",
		FindingClass: "MISCONFIGURATION",
		RiskScore:  &models.RiskScore{Total: 60},
	}
	gen.Generate(f)

	if f.Remediation == nil {
		t.Fatal("Remediation should not be nil for HIGH findings")
	}
	if f.Remediation.RemediationScript != "" {
		t.Error("HIGH finding should NOT have a RemediationScript (CRITICAL only)")
	}
	if f.Remediation.RemediationScriptLang != "" {
		t.Error("HIGH finding should NOT have a RemediationScriptLang")
	}
}

func TestGenerate_SummaryAlwaysSet(t *testing.T) {
	gen := remediation.NewGenerator()
	for _, priority := range []string{"CRITICAL", "HIGH", "MEDIUM", "LOW"} {
		f := &models.Finding{
			Category:  "FLOW_LOGS_DISABLED",
			Priority:  priority,
			ProjectID: "proj",
			RiskScore: &models.RiskScore{Total: 80},
		}
		gen.Generate(f)
		if f.Remediation == nil || f.Remediation.Summary == "" {
			t.Errorf("priority %s: Remediation.Summary should be set", priority)
		}
	}
}

// ── helpers ──────────────────────────────────────────────────────────────────

func criticalFinding(category, resourceName, projectID string) *models.Finding {
	return &models.Finding{
		Name:         "organizations/123/sources/456/findings/abc001",
		Category:     category,
		Priority:     models.PriorityCritical,
		Severity:     "HIGH",
		FindingClass: "VULNERABILITY",
		ResourceName: resourceName,
		ProjectID:    projectID,
		RiskScore:    &models.RiskScore{Total: 90},
		CreateTime:   time.Now(),
		EventTime:    time.Now(),
	}
}
