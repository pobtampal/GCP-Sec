#!/usr/bin/env bash
# ============================================================
# Finding:   dfb2ade7956a4b71ab18ccc122e5bd98
# Category:  SERVICE ACCOUNT THAT EXPOSES MANY VALUED RESOURCES
# Priority:  CRITICAL (risk score 75.00)
# Resource:  projects/wanaware-core-stage/serviceAccounts/tf-deploy@wanaware-core-stage.iam.gserviceaccount.com
# Project:   940510641271
# Generated: 2026-02-22
# ============================================================
set -euo pipefail

PROJECT="940510641271"
RESOURCE="projects/wanaware-core-stage/serviceAccounts/tf-deploy@wanaware-core-stage.iam.gserviceaccount.com"
CATEGORY="SERVICE ACCOUNT THAT EXPOSES MANY VALUED RESOURCES"
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
