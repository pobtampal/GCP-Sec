#!/usr/bin/env bash
# ============================================================
# Finding:   9bba748d26862e8dff96ed933fad0ffe
# Category:  SERVICE ACCOUNT KEY THAT EXPOSES MANY VALUED RESOURCES
# Priority:  CRITICAL (risk score 75.00)
# Resource:  projects/wanaware-core-stage/serviceAccounts/tf-deploy@wanaware-core-stage.iam.gserviceaccount.com/keys/ea1df4bb2acc76d8973fd9bd7998d8a5da53aec5
# Project:   940510641271
# Generated: 2026-02-22
# ============================================================
set -euo pipefail

PROJECT="940510641271"
RESOURCE="projects/wanaware-core-stage/serviceAccounts/tf-deploy@wanaware-core-stage.iam.gserviceaccount.com/keys/ea1df4bb2acc76d8973fd9bd7998d8a5da53aec5"
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
