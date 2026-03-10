// Package remediation provides structured remediation guidance for security findings.
package remediation

import (
	"fmt"
	"strings"

	"github.com/wanaware/GCP-Sec/internal/models"
)

// Generator produces remediation steps for findings.
type Generator struct{}

// NewGenerator creates a new remediation Generator.
func NewGenerator() *Generator { return &Generator{} }

// Generate produces a RemediationStep for the given finding.
func (g *Generator) Generate(f *models.Finding) *models.RemediationStep {
	r := &models.RemediationStep{}

	r.NextSteps = g.parseNextSteps(f.NextSteps)
	r.ResourceLinks = g.resourceLinks(f)
	r.EstimatedEffort = g.estimatedEffort(f)
	r.AutomationPotential, r.AutomationHint = g.automationPotential(f)
	r.PriorityRationale = g.priorityRationale(f)
	r.Summary = g.summary(f)

	// Generate a full, finding-specific remediation script for CRITICAL findings.
	// Scoring always runs before Generate() is called, so f.Priority is set here.
	if f.Priority == models.PriorityCritical {
		sg := NewScriptGenerator()
		r.RemediationScript, r.RemediationScriptLang = sg.Generate(f)
	}

	f.Remediation = r
	return r
}

// GenerateAll attaches remediation steps to all findings.
func (g *Generator) GenerateAll(findings []*models.Finding) {
	for _, f := range findings {
		g.Generate(f)
	}
}

// parseNextSteps converts the raw next_steps string into a bulleted list.
func (g *Generator) parseNextSteps(raw string) []string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return []string{"Review the finding details in GCP Security Command Center."}
	}
	var steps []string
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		// Strip leading list markers (1. 2. - * •)
		for _, prefix := range []string{"- ", "* ", "• "} {
			line = strings.TrimPrefix(line, prefix)
		}
		line = strings.TrimSpace(line)
		if line != "" {
			steps = append(steps, line)
		}
	}
	if len(steps) == 0 {
		for _, part := range strings.Split(raw, ";") {
			part = strings.TrimSpace(part)
			if part != "" {
				steps = append(steps, part)
			}
		}
	}
	if len(steps) == 0 {
		steps = []string{raw}
	}
	return steps
}

// resourceLinks returns documentation links relevant to the finding category.
func (g *Generator) resourceLinks(f *models.Finding) []string {
	cat := strings.ToUpper(f.Category)
	var links []string

	switch {
	case strings.Contains(cat, "CONTAINER_IMAGE") || strings.Contains(cat, "VULNERABILITY"):
		links = append(links,
			"https://cloud.google.com/container-analysis/docs/container-scanning-overview",
			"https://cloud.google.com/security-command-center/docs/how-to-remediate-container-threats",
		)
	case strings.Contains(cat, "FLOW_LOGS"):
		links = append(links,
			"https://cloud.google.com/vpc/docs/using-flow-logs",
			"https://cloud.google.com/security-command-center/docs/how-to-remediate-network-flow-logs",
		)
	case strings.Contains(cat, "PRIVATE_GOOGLE_ACCESS"):
		links = append(links,
			"https://cloud.google.com/vpc/docs/configure-private-google-access",
		)
	case strings.Contains(cat, "FIREWALL"):
		links = append(links,
			"https://cloud.google.com/vpc/docs/firewalls",
			"https://cloud.google.com/security-command-center/docs/how-to-remediate-firewall-threats",
		)
	case strings.Contains(cat, "IAM") || strings.Contains(cat, "SERVICE_ACCOUNT"):
		links = append(links,
			"https://cloud.google.com/iam/docs/best-practices-for-using-and-managing-service-accounts",
			"https://cloud.google.com/security-command-center/docs/how-to-remediate-iam-threats",
		)
	case strings.Contains(cat, "AUDIT") || strings.Contains(cat, "LOGGING"):
		links = append(links,
			"https://cloud.google.com/logging/docs/audit",
			"https://cloud.google.com/security-command-center/docs/how-to-remediate-logging-threats",
		)
	case strings.Contains(cat, "BUCKET") || strings.Contains(cat, "STORAGE"):
		links = append(links,
			"https://cloud.google.com/storage/docs/best-practices",
			"https://cloud.google.com/security-command-center/docs/how-to-remediate-storage-threats",
		)
	case strings.Contains(cat, "SSL") || strings.Contains(cat, "TLS"):
		links = append(links,
			"https://cloud.google.com/load-balancing/docs/ssl-policies-concepts",
		)
	}

	if f.HasCVE() {
		links = append(links, "https://nvd.nist.gov/vuln/detail/"+f.CVEID)
	}
	links = append(links,
		"https://cloud.google.com/security-command-center/docs/concepts-security-command-center-overview",
	)
	return links
}

// estimatedEffort returns a human-readable effort estimate.
func (g *Generator) estimatedEffort(f *models.Finding) string {
	cat := strings.ToUpper(f.Category)
	switch {
	case strings.Contains(cat, "FLOW_LOGS") ||
		strings.Contains(cat, "PRIVATE_GOOGLE_ACCESS") ||
		strings.Contains(cat, "BUCKET_LOGGING"):
		return "Low (< 30 minutes) — single API call or console toggle"
	case strings.Contains(cat, "FIREWALL"):
		return "Medium (1-2 hours) — requires firewall rule analysis and update"
	case strings.Contains(cat, "IAM") || strings.Contains(cat, "SERVICE_ACCOUNT"):
		return "Medium (2-4 hours) — requires IAM policy review and update"
	case strings.Contains(cat, "CONTAINER") || strings.Contains(cat, "VULNERABILITY"):
		return "High (1-3 days) — requires image rebuild and redeployment"
	case strings.Contains(cat, "SSL") || strings.Contains(cat, "TLS"):
		return "Medium (1-2 hours) — requires policy update and possible cert rotation"
	default:
		switch f.FindingClass {
		case "MISCONFIGURATION":
			return "Low-Medium (30 min - 2 hours)"
		case "VULNERABILITY":
			return "Medium-High (2 hours - 2 days)"
		case "THREAT":
			return "High (immediate investigation required)"
		default:
			return "Medium (1-2 hours)"
		}
	}
}

// automationPotential returns an automation level and example hint command.
func (g *Generator) automationPotential(f *models.Finding) (level, hint string) {
	cat := strings.ToUpper(f.Category)
	switch {
	case strings.Contains(cat, "FLOW_LOGS"):
		return "High",
			"gcloud compute networks subnets update SUBNET --enable-flow-logs --region=REGION"
	case strings.Contains(cat, "PRIVATE_GOOGLE_ACCESS"):
		return "High",
			"gcloud compute networks subnets update SUBNET --enable-private-ip-google-access --region=REGION"
	case strings.Contains(cat, "BUCKET_LOGGING"):
		return "High",
			"gsutil logging set on -b gs://LOG_BUCKET gs://TARGET_BUCKET"
	case strings.Contains(cat, "AUDIT"):
		return "High",
			"gcloud projects set-iam-policy PROJECT_ID policy.json  # with auditConfigs block"
	case strings.Contains(cat, "FIREWALL"):
		return "Medium",
			"gcloud compute firewall-rules update RULE_NAME --disabled  # then review and restrict"
	case strings.Contains(cat, "SERVICE_ACCOUNT_KEY"):
		return "Medium",
			"gcloud iam service-accounts keys delete KEY_ID --iam-account=SA_EMAIL"
	case strings.Contains(cat, "CONTAINER") || strings.Contains(cat, "VULNERABILITY"):
		return "Low",
			"# Rebuild container image with updated base image and patched dependencies"
	case strings.Contains(cat, "SSL") || strings.Contains(cat, "TLS"):
		return "Medium",
			"gcloud compute ssl-policies create POLICY --profile=MODERN --min-tls-version=TLS_1_2"
	default:
		return "Medium", "Refer to GCP documentation for CLI/Terraform automation options"
	}
}

// summary generates a one-line description of what needs to be done.
func (g *Generator) summary(f *models.Finding) string {
	cat := strings.ToUpper(f.Category)
	resource := f.ResourceDisplayName
	if resource == "" {
		resource = f.ResourceName
	}
	switch {
	case strings.Contains(cat, "FLOW_LOGS"):
		return "Enable VPC Flow Logs on the affected subnet"
	case strings.Contains(cat, "PRIVATE_GOOGLE_ACCESS"):
		return "Enable Private Google Access on the affected subnet"
	case strings.Contains(cat, "FIREWALL"):
		return "Review and restrict overly permissive firewall rules"
	case strings.Contains(cat, "BUCKET_LOGGING"):
		return "Enable access logging on the Cloud Storage bucket"
	case strings.Contains(cat, "CONTAINER") || strings.Contains(cat, "VULNERABILITY"):
		return "Update and rebuild the container image to patch the vulnerability"
	case strings.Contains(cat, "SERVICE_ACCOUNT_KEY"):
		return "Rotate or delete unused service account keys"
	case strings.Contains(cat, "IAM"):
		return "Review and restrict IAM permissions to least privilege"
	case strings.Contains(cat, "AUDIT"):
		return "Enable audit logging for all relevant services"
	case strings.Contains(cat, "SSL") || strings.Contains(cat, "TLS"):
		return "Update SSL/TLS policy to use modern, strong cipher suites"
	default:
		if resource != "" {
			return fmt.Sprintf("Remediate %s finding on %s", f.Category, resource)
		}
		return fmt.Sprintf("Remediate %s finding", f.Category)
	}
}

// priorityRationale explains why the finding received its priority.
func (g *Generator) priorityRationale(f *models.Finding) string {
	if f.RiskScore == nil {
		return "Risk score not calculated"
	}
	rs := f.RiskScore
	var reasons []string

	reasons = append(reasons, "Severity: "+f.Severity)
	if rs.CVSSComponent > 0 {
		reasons = append(reasons, fmt.Sprintf("CVSS: %.1f", f.CVSSScore))
	}
	if f.ObservedInWild {
		reasons = append(reasons, "actively exploited in the wild")
	}
	if f.ZeroDay {
		reasons = append(reasons, "zero-day vulnerability")
	}
	if f.PublicIPAddress {
		reasons = append(reasons, "public IP exposure")
	}
	if len(f.ComplianceFrameworks) > 0 {
		reasons = append(reasons, "compliance: "+strings.Join(f.ComplianceFrameworks, ", "))
	}
	return fmt.Sprintf("%s → risk score %.2f → %s",
		strings.Join(reasons, "; "), rs.Total, f.Priority)
}
