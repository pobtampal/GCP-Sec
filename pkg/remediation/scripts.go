package remediation

import (
	"fmt"
	"strings"
	"time"

	"github.com/wanaware/GCP-Sec/internal/models"
)

// ScriptGenerator produces finding-specific remediation scripts for CRITICAL findings.
// Language selection: bash for CLI-automatable tasks, python3 for complex multi-step remediation.
type ScriptGenerator struct{}

// NewScriptGenerator creates a new ScriptGenerator.
func NewScriptGenerator() *ScriptGenerator { return &ScriptGenerator{} }

// Generate returns (script, lang) for the given CRITICAL finding.
// lang is "bash" or "python3". Unrecognised categories get a generic bash inspection script.
func (sg *ScriptGenerator) Generate(f *models.Finding) (script, lang string) {
	cat := strings.ToUpper(f.Category)

	switch {
	case strings.Contains(cat, "FLOW_LOGS"):
		return sg.flowLogsScript(f), "bash"
	case strings.Contains(cat, "PRIVATE_GOOGLE_ACCESS"):
		return sg.privateGoogleAccessScript(f), "bash"
	case strings.Contains(cat, "BUCKET_LOGGING"):
		return sg.bucketLoggingScript(f), "bash"
	case strings.Contains(cat, "AUDIT_LOGGING") ||
		(strings.Contains(cat, "AUDIT") && strings.Contains(cat, "DISABLED")):
		return sg.auditLoggingScript(f), "bash"
	case strings.Contains(cat, "FIREWALL_RULE_LOGGING"):
		return sg.firewallLoggingScript(f), "bash"
	case strings.Contains(cat, "OPEN_FIREWALL"):
		return sg.openFirewallScript(f), "bash"
	case strings.Contains(cat, "WEAK_SSL"):
		return sg.weakSSLScript(f), "bash"
	case strings.Contains(cat, "SERVICE_ACCOUNT_KEY"):
		return sg.serviceAccountKeyScript(f), "bash"
	case strings.Contains(cat, "ANOMALOUS_IAM") || strings.Contains(cat, "IAM_GRANT"):
		return sg.iamAnomalyScript(f), "bash"
	case strings.Contains(cat, "CONTAINER_IMAGE"):
		return sg.containerVulnScript(f), "python3"
	case strings.Contains(cat, "OS_VULNERABILITY"):
		return sg.osVulnScript(f), "python3"
	default:
		return sg.defaultScript(f), "bash"
	}
}

// ──────────────────────────────────────────────────────────────────────────────
// Helpers
// ──────────────────────────────────────────────────────────────────────────────

// parseResourceName splits a GCP API resource name into named path segments.
//
// Examples:
//
//	//compute.googleapis.com/projects/proj/regions/us-central1/subnetworks/my-subnet
//	//container.googleapis.com/projects/proj/zones/us-central1-a/clusters/prod
//	//storage.googleapis.com/projects/proj/buckets/my-bucket
//	//iam.googleapis.com/projects/proj/serviceAccounts/sa@p.iam.gserviceaccount.com/keys/abc
//	//compute.googleapis.com/projects/proj/global/firewalls/allow-ssh
func parseResourceName(resourceName string) map[string]string {
	result := map[string]string{
		"project": "", "region": "", "zone": "",
		"subnet": "", "cluster": "", "bucket": "",
		"firewall": "", "instance": "", "sa": "", "key": "",
	}

	// Strip leading "//"
	s := strings.TrimPrefix(resourceName, "//")

	// Split off the service host: "compute.googleapis.com/projects/..."
	slashIdx := strings.Index(s, "/")
	if slashIdx < 0 {
		return result
	}
	path := s[slashIdx+1:] // e.g. "projects/proj/regions/us-central1/subnetworks/my-subnet"

	parts := strings.Split(path, "/")
	// Walk key/value pairs. "global" has no paired value and is skipped gracefully.
	for i := 0; i+1 < len(parts); i += 2 {
		k, v := parts[i], parts[i+1]
		switch k {
		case "projects":
			result["project"] = v
		case "regions":
			result["region"] = v
		case "zones":
			result["zone"] = v
		case "subnetworks":
			result["subnet"] = v
		case "clusters":
			result["cluster"] = v
		case "buckets":
			result["bucket"] = v
		case "firewalls":
			result["firewall"] = v
		case "instances":
			result["instance"] = v
		case "serviceAccounts":
			result["sa"] = v
		case "keys":
			result["key"] = v
		}
	}
	return result
}

// orDefault returns val if non-empty, otherwise fallback.
func orDefault(val, fallback string) string {
	if val != "" {
		return val
	}
	return fallback
}

// scriptHeader builds the standardised comment block embedded at the top of every script.
func (sg *ScriptGenerator) scriptHeader(f *models.Finding) string {
	resource := f.ResourceDisplayName
	if resource == "" {
		resource = f.ResourceName
	}
	cveInfo := ""
	if f.CVEID != "" {
		cveInfo = fmt.Sprintf("\n# CVE:           %s (CVSS %.1f)", f.CVEID, f.CVSSScore)
	}
	riskTotal := 0.0
	if f.RiskScore != nil {
		riskTotal = f.RiskScore.Total
	}
	return fmt.Sprintf(
		"# ============================================================\n"+
			"# Finding:   %s\n"+
			"# Category:  %s\n"+
			"# Priority:  %s (risk score %.2f)\n"+
			"# Resource:  %s\n"+
			"# Project:   %s%s\n"+
			"# Generated: %s\n"+
			"# ============================================================",
		f.ShortName(),
		f.Category,
		f.Priority,
		riskTotal,
		resource,
		f.ProjectID,
		cveInfo,
		time.Now().UTC().Format("2006-01-02"),
	)
}

// ──────────────────────────────────────────────────────────────────────────────
// Bash script generators
// ──────────────────────────────────────────────────────────────────────────────

func (sg *ScriptGenerator) flowLogsScript(f *models.Finding) string {
	seg := parseResourceName(f.ResourceName)
	project := orDefault(seg["project"], f.ProjectID)
	region := orDefault(seg["region"], "UNKNOWN_REGION")
	subnet := orDefault(seg["subnet"], f.ResourceDisplayName)

	return fmt.Sprintf(`#!/usr/bin/env bash
%s
set -euo pipefail

# ── Variables (verify before running) ──────────────────────────
PROJECT=%q
REGION=%q
SUBNET=%q
DRY_RUN=${DRY_RUN:-false}

echo "[INFO] Looking up subnet ${SUBNET} in project ${PROJECT}, region ${REGION}..."
gcloud compute networks subnets describe "${SUBNET}" \
  --region="${REGION}" \
  --project="${PROJECT}" \
  --format="value(name,enableFlowLogs)"

if [[ "${DRY_RUN}" == "true" ]]; then
  echo "[DRY-RUN] Would enable flow logs on subnet ${SUBNET} (project=${PROJECT}, region=${REGION})"
  exit 0
fi

echo "[INFO] Enabling VPC Flow Logs on subnet ${SUBNET}..."
gcloud compute networks subnets update "${SUBNET}" \
  --region="${REGION}" \
  --project="${PROJECT}" \
  --enable-flow-logs \
  --logging-aggregation-interval=INTERVAL_5_SEC \
  --logging-flow-sampling=0.5 \
  --logging-metadata=INCLUDE_ALL_METADATA

echo "[OK] VPC Flow Logs enabled on ${SUBNET}."
`, sg.scriptHeader(f), project, region, subnet)
}

func (sg *ScriptGenerator) privateGoogleAccessScript(f *models.Finding) string {
	seg := parseResourceName(f.ResourceName)
	project := orDefault(seg["project"], f.ProjectID)
	region := orDefault(seg["region"], "UNKNOWN_REGION")
	subnet := orDefault(seg["subnet"], f.ResourceDisplayName)

	return fmt.Sprintf(`#!/usr/bin/env bash
%s
set -euo pipefail

PROJECT=%q
REGION=%q
SUBNET=%q
DRY_RUN=${DRY_RUN:-false}

echo "[INFO] Current Private Google Access status:"
gcloud compute networks subnets describe "${SUBNET}" \
  --region="${REGION}" \
  --project="${PROJECT}" \
  --format="value(name,privateIpGoogleAccess)"

if [[ "${DRY_RUN}" == "true" ]]; then
  echo "[DRY-RUN] Would enable Private Google Access on ${SUBNET}"
  exit 0
fi

echo "[INFO] Enabling Private Google Access on subnet ${SUBNET}..."
gcloud compute networks subnets update "${SUBNET}" \
  --region="${REGION}" \
  --project="${PROJECT}" \
  --enable-private-ip-google-access

echo "[OK] Private Google Access enabled on ${SUBNET}."
`, sg.scriptHeader(f), project, region, subnet)
}

func (sg *ScriptGenerator) bucketLoggingScript(f *models.Finding) string {
	seg := parseResourceName(f.ResourceName)
	project := orDefault(seg["project"], f.ProjectID)
	bucket := orDefault(seg["bucket"], f.ResourceDisplayName)
	logBucket := project + "-audit-logs"

	return fmt.Sprintf(`#!/usr/bin/env bash
%s
set -euo pipefail

PROJECT=%q
TARGET_BUCKET=%q
LOG_BUCKET=${LOG_BUCKET:-%q}
DRY_RUN=${DRY_RUN:-false}

echo "[INFO] Checking current logging config for gs://${TARGET_BUCKET}..."
gsutil logging get "gs://${TARGET_BUCKET}" || echo "(no logging configured)"

if ! gsutil ls "gs://${LOG_BUCKET}" > /dev/null 2>&1; then
  if [[ "${DRY_RUN}" == "true" ]]; then
    echo "[DRY-RUN] Would create log bucket gs://${LOG_BUCKET}"
  else
    echo "[INFO] Creating log bucket gs://${LOG_BUCKET}..."
    gsutil mb -p "${PROJECT}" "gs://${LOG_BUCKET}"
    gsutil versioning set on "gs://${LOG_BUCKET}"
  fi
fi

if [[ "${DRY_RUN}" == "true" ]]; then
  echo "[DRY-RUN] Would run: gsutil logging set on -b gs://${LOG_BUCKET} gs://${TARGET_BUCKET}"
  exit 0
fi

echo "[INFO] Enabling access logging on gs://${TARGET_BUCKET}..."
gsutil logging set on -b "gs://${LOG_BUCKET}" "gs://${TARGET_BUCKET}"
echo "[OK] Access logging enabled — logs written to gs://${LOG_BUCKET}."
`, sg.scriptHeader(f), project, bucket, logBucket)
}

func (sg *ScriptGenerator) auditLoggingScript(f *models.Finding) string {
	seg := parseResourceName(f.ResourceName)
	project := orDefault(seg["project"], f.ProjectID)

	return fmt.Sprintf(`#!/usr/bin/env bash
%s
set -euo pipefail

PROJECT=%q
DRY_RUN=${DRY_RUN:-false}
POLICY_FILE="/tmp/iam-policy-${PROJECT}-$$.json"
MERGED_FILE="/tmp/iam-policy-merged-${PROJECT}-$$.json"

echo "[INFO] Fetching current IAM policy for project ${PROJECT}..."
gcloud projects get-iam-policy "${PROJECT}" --format=json > "${POLICY_FILE}"

echo "[INFO] Current auditConfigs:"
python3 -c "
import json
with open('${POLICY_FILE}') as f:
    p = json.load(f)
print(json.dumps(p.get('auditConfigs', []), indent=2))
"

if [[ "${DRY_RUN}" == "true" ]]; then
  echo "[DRY-RUN] Would merge DATA_READ, DATA_WRITE, ADMIN_READ audit configs for allServices"
  rm -f "${POLICY_FILE}"
  exit 0
fi

echo "[INFO] Merging audit logging config..."
POLICY_FILE="${POLICY_FILE}" MERGED_FILE="${MERGED_FILE}" python3 - <<'PY_EOF'
import json, os

policy_file = os.environ["POLICY_FILE"]
merged_file = os.environ["MERGED_FILE"]

with open(policy_file) as f:
    policy = json.load(f)

new_cfg = [{"service": "allServices", "auditLogConfigs": [
    {"logType": "ADMIN_READ"}, {"logType": "DATA_READ"}, {"logType": "DATA_WRITE"}
]}]
existing = {ac["service"]: ac for ac in policy.get("auditConfigs", [])}
for ac in new_cfg:
    existing[ac["service"]] = ac
policy["auditConfigs"] = list(existing.values())

with open(merged_file, "w") as f:
    json.dump(policy, f, indent=2)
print("[OK] Merged audit config written to", merged_file)
PY_EOF

gcloud projects set-iam-policy "${PROJECT}" "${MERGED_FILE}"
echo "[OK] Audit logging enabled for all services in project ${PROJECT}."
rm -f "${POLICY_FILE}" "${MERGED_FILE}"
`, sg.scriptHeader(f), project)
}

func (sg *ScriptGenerator) firewallLoggingScript(f *models.Finding) string {
	seg := parseResourceName(f.ResourceName)
	project := orDefault(seg["project"], f.ProjectID)
	firewall := orDefault(seg["firewall"], f.ResourceDisplayName)

	return fmt.Sprintf(`#!/usr/bin/env bash
%s
set -euo pipefail

PROJECT=%q
FIREWALL_RULE=%q
DRY_RUN=${DRY_RUN:-false}

echo "[INFO] Current firewall rule configuration:"
gcloud compute firewall-rules describe "${FIREWALL_RULE}" \
  --project="${PROJECT}" \
  --format="table(name,logConfig.enable,direction,priority,sourceRanges,allowed)"

if [[ "${DRY_RUN}" == "true" ]]; then
  echo "[DRY-RUN] Would enable logging on firewall rule ${FIREWALL_RULE}"
  exit 0
fi

echo "[INFO] Enabling firewall rule logging on ${FIREWALL_RULE}..."
gcloud compute firewall-rules update "${FIREWALL_RULE}" \
  --project="${PROJECT}" \
  --enable-logging

echo "[OK] Firewall rule logging enabled on ${FIREWALL_RULE}."
`, sg.scriptHeader(f), project, firewall)
}

func (sg *ScriptGenerator) openFirewallScript(f *models.Finding) string {
	seg := parseResourceName(f.ResourceName)
	project := orDefault(seg["project"], f.ProjectID)
	firewall := orDefault(seg["firewall"], f.ResourceDisplayName)

	return fmt.Sprintf(`#!/usr/bin/env bash
%s
set -euo pipefail

PROJECT=%q
FIREWALL_RULE=%q
# Set ALLOWED_SOURCE_RANGE to your trusted CIDR before running.
ALLOWED_SOURCE_RANGE=${ALLOWED_SOURCE_RANGE:-"10.0.0.0/8"}
DRY_RUN=${DRY_RUN:-false}

echo "[WARN] This rule currently allows 0.0.0.0/0. Review before proceeding."
echo "[INFO] Current rule state:"
gcloud compute firewall-rules describe "${FIREWALL_RULE}" \
  --project="${PROJECT}" \
  --format="table(name,direction,priority,sourceRanges,allowed,disabled)"

if [[ "${DRY_RUN}" == "true" ]]; then
  echo "[DRY-RUN] Would restrict ${FIREWALL_RULE} to source range ${ALLOWED_SOURCE_RANGE}"
  exit 0
fi

echo "[INFO] Disabling rule ${FIREWALL_RULE} to stop public exposure..."
gcloud compute firewall-rules update "${FIREWALL_RULE}" \
  --project="${PROJECT}" \
  --disabled

echo "[INFO] Restricting source ranges to ${ALLOWED_SOURCE_RANGE}..."
gcloud compute firewall-rules update "${FIREWALL_RULE}" \
  --project="${PROJECT}" \
  --source-ranges="${ALLOWED_SOURCE_RANGE}"

echo "[INFO] Re-enabling rule with restricted access..."
gcloud compute firewall-rules update "${FIREWALL_RULE}" \
  --project="${PROJECT}" \
  --no-disabled

echo "[OK] Firewall rule ${FIREWALL_RULE} now restricted to ${ALLOWED_SOURCE_RANGE}."
`, sg.scriptHeader(f), project, firewall)
}

func (sg *ScriptGenerator) weakSSLScript(f *models.Finding) string {
	seg := parseResourceName(f.ResourceName)
	project := orDefault(seg["project"], f.ProjectID)
	resource := f.ResourceDisplayName
	if resource == "" {
		resource = f.ResourceName
	}

	return fmt.Sprintf(`#!/usr/bin/env bash
%s
set -euo pipefail

PROJECT=%q
RESOURCE=%q
SSL_POLICY_NAME="modern-ssl-policy"
DRY_RUN=${DRY_RUN:-false}

echo "[INFO] Existing SSL policies in project ${PROJECT}:"
gcloud compute ssl-policies list \
  --project="${PROJECT}" \
  --format="table(name,profile,minTlsVersion)"

if gcloud compute ssl-policies describe "${SSL_POLICY_NAME}" \
    --project="${PROJECT}" > /dev/null 2>&1; then
  echo "[INFO] SSL policy ${SSL_POLICY_NAME} already exists."
else
  if [[ "${DRY_RUN}" == "true" ]]; then
    echo "[DRY-RUN] Would create SSL policy ${SSL_POLICY_NAME} (MODERN, TLS_1_2)"
  else
    echo "[INFO] Creating modern SSL policy: ${SSL_POLICY_NAME}..."
    gcloud compute ssl-policies create "${SSL_POLICY_NAME}" \
      --project="${PROJECT}" \
      --profile=MODERN \
      --min-tls-version=TLS_1_2
    echo "[OK] SSL policy ${SSL_POLICY_NAME} created."
  fi
fi

echo ""
echo "[ACTION REQUIRED] Attach the policy to the HTTPS proxy for ${RESOURCE}:"
echo "  gcloud compute target-https-proxies update ${RESOURCE} \\"
echo "    --ssl-policy=${SSL_POLICY_NAME} --project=${PROJECT}"
`, sg.scriptHeader(f), project, resource)
}

func (sg *ScriptGenerator) serviceAccountKeyScript(f *models.Finding) string {
	seg := parseResourceName(f.ResourceName)
	project := orDefault(seg["project"], f.ProjectID)
	saEmail := orDefault(seg["sa"], f.ResourceDisplayName)
	keyID := seg["key"]

	return fmt.Sprintf(`#!/usr/bin/env bash
%s
set -euo pipefail

PROJECT=%q
SA_EMAIL=%q
KEY_ID=%q
DRY_RUN=${DRY_RUN:-false}

echo "[INFO] User-managed keys for ${SA_EMAIL}:"
gcloud iam service-accounts keys list \
  --iam-account="${SA_EMAIL}" \
  --project="${PROJECT}" \
  --managed-by=user \
  --format="table(name.basename(),validAfterTime,validBeforeTime,keyType)"

if [[ -z "${KEY_ID}" ]]; then
  echo "[WARN] No specific key ID found. Set KEY_ID=<key_id> before running deletion."
  exit 1
fi

if [[ "${DRY_RUN}" == "true" ]]; then
  echo "[DRY-RUN] Would create a replacement key, then delete key ${KEY_ID}"
  exit 0
fi

NEW_KEY_FILE="sa-key-$(date +%%Y%%m%%d%%H%%M%%S).json"
echo "[INFO] Creating replacement key (update all consumers before continuing)..."
gcloud iam service-accounts keys create "${NEW_KEY_FILE}" \
  --iam-account="${SA_EMAIL}" \
  --project="${PROJECT}"
echo "[OK] New key written to ${NEW_KEY_FILE}"

read -rp "Press Enter once all consumers are updated with the new key, or Ctrl+C to abort..."

echo "[INFO] Deleting old key ${KEY_ID}..."
gcloud iam service-accounts keys delete "${KEY_ID}" \
  --iam-account="${SA_EMAIL}" \
  --project="${PROJECT}" \
  --quiet

echo "[OK] Key ${KEY_ID} deleted."
`, sg.scriptHeader(f), project, saEmail, keyID)
}

func (sg *ScriptGenerator) iamAnomalyScript(f *models.Finding) string {
	seg := parseResourceName(f.ResourceName)
	project := orDefault(seg["project"], f.ProjectID)

	return fmt.Sprintf(`#!/usr/bin/env bash
%s
set -euo pipefail

PROJECT=%q
DRY_RUN=${DRY_RUN:-false}

echo "[INFO] Current IAM bindings for project ${PROJECT}:"
gcloud projects get-iam-policy "${PROJECT}" \
  --format="table(bindings.role,bindings.members.flatten())"

echo ""
echo "[INFO] Recent IAM policy changes (last 7 days from Cloud Audit Logs):"
gcloud logging read \
  'protoPayload.methodName="SetIamPolicy" OR protoPayload.methodName="google.iam.admin.v1.UpdateServiceAccount"' \
  --project="${PROJECT}" \
  --freshness=7d \
  --limit=20 \
  --format="table(timestamp,protoPayload.authenticationInfo.principalEmail,protoPayload.methodName)"

echo ""
echo "[WARN] Review the bindings above for unexpected owner/editor grants."
echo "       To remove a suspicious binding, run:"
echo "  gcloud projects remove-iam-policy-binding ${PROJECT} \\"
echo "    --member='MEMBER_TO_REMOVE' \\"
echo "    --role='roles/ROLE_TO_REMOVE'"
`, sg.scriptHeader(f), project)
}

// ──────────────────────────────────────────────────────────────────────────────
// Python script generators
// ──────────────────────────────────────────────────────────────────────────────

func (sg *ScriptGenerator) containerVulnScript(f *models.Finding) string {
	seg := parseResourceName(f.ResourceName)
	project := orDefault(seg["project"], f.ProjectID)
	cluster := orDefault(seg["cluster"], "UNKNOWN_CLUSTER")
	zone := orDefault(seg["zone"], "UNKNOWN_ZONE")
	pod := f.ResourceDisplayName
	if pod == "" {
		pod = "UNKNOWN_POD"
	}

	return fmt.Sprintf(`#!/usr/bin/env python3
%s

import subprocess
import sys
import json

PROJECT  = %q
CLUSTER  = %q
ZONE     = %q
POD_NAME = %q
CVE_ID   = %q
CVSS     = %.1f
DRY_RUN  = False  # set to True to skip cluster authentication

def run(cmd, capture=True, check=True):
    print(f"[CMD] {' '.join(cmd)}")
    result = subprocess.run(cmd, capture_output=capture, text=True)
    if check and result.returncode != 0:
        print(f"[ERROR] {result.stderr.strip()}", file=sys.stderr)
        sys.exit(1)
    return result.stdout.strip() if capture else ""

def main():
    print(f"[INFO] Container vulnerability: {CVE_ID} (CVSS {CVSS})")
    print(f"[INFO] Pod: {POD_NAME}  Cluster: {CLUSTER}  Zone: {ZONE}  Project: {PROJECT}")
    print()

    # Step 1: Query Container Analysis API
    print("[INFO] Checking Container Analysis for vulnerability occurrences...")
    try:
        out = run([
            "gcloud", "artifacts", "vulnerabilities", "list-occurrences",
            "--project", PROJECT, "--format", "json",
            "--filter", f"vulnerability.cveId={CVE_ID}",
        ], check=False)
        occurrences = json.loads(out) if out else []
        if occurrences:
            print(f"[INFO] Found {len(occurrences)} affected image(s):")
            for occ in occurrences[:5]:
                print(f"  - {occ.get('resourceUri', 'unknown')}")
        else:
            print(f"[INFO] No Container Analysis occurrences for {CVE_ID}.")
    except Exception as e:
        print(f"[WARN] Could not query Container Analysis: {e}")
    print()

    # Step 2: Get cluster credentials and inspect pod
    if not DRY_RUN:
        print(f"[INFO] Getting credentials for cluster {CLUSTER}...")
        run(["gcloud", "container", "clusters", "get-credentials",
             CLUSTER, "--zone", ZONE, "--project", PROJECT], capture=False)

        print(f"[INFO] Checking images in pod {POD_NAME}...")
        try:
            pod_json = run(["kubectl", "get", "pod", POD_NAME, "-o", "json"])
            pod = json.loads(pod_json)
            for c in pod.get("spec", {}).get("containers", []):
                print(f"  Container: {c['name']}  Image: {c.get('image', 'unknown')}")
        except Exception as e:
            print(f"[WARN] Could not inspect pod: {e}")
        print()

    # Step 3: Remediation steps
    print(f"""[ACTION REQUIRED] Remediate {CVE_ID}:

1. Update the Dockerfile to use a patched base image.
2. Rebuild and push the new image:
       docker build -t gcr.io/{PROJECT}/<image-name>:<new-tag> .
       docker push gcr.io/{PROJECT}/<image-name>:<new-tag>
3. Update the Kubernetes deployment:
       kubectl set image deployment/<DEPLOYMENT> <CONTAINER>=gcr.io/{PROJECT}/<image-name>:<new-tag>
4. Verify the fix:
       gcloud artifacts vulnerabilities scan gcr.io/{PROJECT}/<image-name>:<new-tag>
""")

if __name__ == "__main__":
    main()
`, sg.scriptHeader(f), project, cluster, zone, pod, f.CVEID, f.CVSSScore)
}

func (sg *ScriptGenerator) osVulnScript(f *models.Finding) string {
	seg := parseResourceName(f.ResourceName)
	project := orDefault(seg["project"], f.ProjectID)
	instance := orDefault(seg["instance"], f.ResourceDisplayName)
	zone := orDefault(seg["zone"], "UNKNOWN_ZONE")

	return fmt.Sprintf(`#!/usr/bin/env python3
%s

import subprocess
import sys
import json

PROJECT  = %q
INSTANCE = %q
ZONE     = %q
CVE_ID   = %q
DRY_RUN  = False

def run(cmd, capture=True, check=True):
    print(f"[CMD] {' '.join(cmd)}")
    result = subprocess.run(cmd, capture_output=capture, text=True)
    if check and result.returncode != 0:
        print(f"[ERROR] {result.stderr.strip()}", file=sys.stderr)
        sys.exit(1)
    return result.stdout.strip() if capture else ""

def main():
    print(f"[INFO] OS vulnerability: {CVE_ID}")
    print(f"[INFO] Instance: {INSTANCE}  Zone: {ZONE}  Project: {PROJECT}")
    print()

    # Step 1: Check OS Config vulnerability report
    print("[INFO] Querying OS Config vulnerability report...")
    try:
        report_json = run([
            "gcloud", "compute", "os-config", "vulnerability-reports", "get",
            INSTANCE, "--zone", ZONE, "--project", PROJECT, "--format", "json",
        ], check=False)
        report = json.loads(report_json) if report_json else {}
        vulns = report.get("vulnerabilities", [])
        matching = [v for v in vulns if CVE_ID in str(v.get("cveId", ""))]
        if matching:
            for v in matching[:3]:
                print(f"  Package: {v.get('packageName')}  "
                      f"Installed: {v.get('installedVersion')}  "
                      f"Fixed in: {v.get('fixedVersion', 'N/A')}")
        else:
            print(f"[INFO] {CVE_ID} not in OS Config report (agent may not be installed).")
    except Exception as e:
        print(f"[WARN] Could not parse OS Config report: {e}")
    print()

    # Step 2: Patch job command
    patch_cmd = [
        "gcloud", "compute", "os-config", "patch-jobs", "execute",
        f"--project={PROJECT}",
        f"--instance-filter-names=zones/{ZONE}/instances/{INSTANCE}",
        "--apt-upgrades-type=stable",
        f"--description=Remediate {CVE_ID}",
    ]
    print("[INFO] Patch command:")
    print("  " + " \\\n  ".join(patch_cmd))
    print()

    if DRY_RUN:
        print("[DRY-RUN] Skipping patch execution.")
        return

    answer = input("Run patch job now? [y/N]: ").strip().lower()
    if answer == "y":
        run(patch_cmd, capture=False)
        print(f"[OK] Patch job launched. Monitor: gcloud compute os-config patch-jobs list --project={PROJECT}")
    else:
        print("[INFO] Skipped. Run the patch command above manually when ready.")

if __name__ == "__main__":
    main()
`, sg.scriptHeader(f), project, instance, zone, f.CVEID)
}

// ──────────────────────────────────────────────────────────────────────────────
// Default script (generic inspection for unrecognised categories)
// ──────────────────────────────────────────────────────────────────────────────

func (sg *ScriptGenerator) defaultScript(f *models.Finding) string {
	project := f.ProjectID
	resource := f.ResourceDisplayName
	if resource == "" {
		resource = f.ResourceName
	}

	return fmt.Sprintf(`#!/usr/bin/env bash
%s
set -euo pipefail

PROJECT=%q
RESOURCE=%q
CATEGORY=%q
DRY_RUN=${DRY_RUN:-false}

echo "[INFO] Inspecting ${CATEGORY} finding on resource: ${RESOURCE}"
echo "[INFO] Project: ${PROJECT}"
echo ""

echo "[INFO] Searching for the resource in Cloud Asset Inventory..."
gcloud asset search-all-resources \
  --project="${PROJECT}" \
  --query="name:${RESOURCE}" \
  --format="table(name,assetType,location,state)" || true

echo ""
echo "[INFO] View this finding in Security Command Center:"
echo "  https://console.cloud.google.com/security/command-center/findings?project=${PROJECT}"
echo ""
echo "[ACTION REQUIRED] Review the finding details and apply remediation steps from the report."
`, sg.scriptHeader(f), project, resource, f.Category)
}
