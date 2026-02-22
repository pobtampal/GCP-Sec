#!/usr/bin/env bash
# ============================================================
# Finding:   c9984fdfea6d259a0ecef4e70566a1f5
# Category:  USER-MANAGED KEYS TO SERVICE ACCOUNT WITH PERMISSIONS TO MODIFY THE METADATA INFORMATION OF AN INSTANCE.
# Priority:  CRITICAL (risk score 75.00)
# Resource:  projects/wa-gcp-test/serviceAccounts/885453410960-compute@developer.gserviceaccount.com
# Project:   885453410960
# Generated: 2026-02-22
# ============================================================
set -euo pipefail

PROJECT="885453410960"
RESOURCE="projects/wa-gcp-test/serviceAccounts/885453410960-compute@developer.gserviceaccount.com"
CATEGORY="USER-MANAGED KEYS TO SERVICE ACCOUNT WITH PERMISSIONS TO MODIFY THE METADATA INFORMATION OF AN INSTANCE."
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
