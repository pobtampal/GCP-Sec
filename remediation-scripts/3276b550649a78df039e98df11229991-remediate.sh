#!/usr/bin/env bash
# ============================================================
# Finding:   3276b550649a78df039e98df11229991
# Category:  POD THAT EXPOSES MANY VALUED RESOURCES
# Priority:  CRITICAL (risk score 75.00)
# Resource:  composer-autohealing-b559c8c94-54rht
# Project:   62518548529
# Generated: 2026-02-22
# ============================================================
set -euo pipefail

PROJECT="62518548529"
RESOURCE="composer-autohealing-b559c8c94-54rht"
CATEGORY="POD THAT EXPOSES MANY VALUED RESOURCES"
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
