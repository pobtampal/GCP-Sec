#!/usr/bin/env bash
# ============================================================
# Finding:   ae8c6663ead1cf656341210e669692c7
# Category:  SERVICE ACCOUNT KEY THAT EXPOSES MANY VALUED RESOURCES
# Priority:  CRITICAL (risk score 75.00)
# Resource:  projects/wa-gcp-test/serviceAccounts/885453410960-compute@developer.gserviceaccount.com/keys/3928389c9c2fe79ce62e2c7ca3bfad0922133dde
# Project:   885453410960
# Generated: 2026-02-22
# ============================================================
set -euo pipefail

PROJECT="885453410960"
RESOURCE="projects/wa-gcp-test/serviceAccounts/885453410960-compute@developer.gserviceaccount.com/keys/3928389c9c2fe79ce62e2c7ca3bfad0922133dde"
CATEGORY="SERVICE ACCOUNT KEY THAT EXPOSES MANY VALUED RESOURCES"
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
