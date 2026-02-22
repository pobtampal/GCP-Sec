#!/usr/bin/env bash
# ============================================================
# Finding:   0a08c17a59002748d4962c3a4794b94f
# Category:  PUBLICLY ACCESSIBLE INSTANCE WITH PROJECT-WIDE SSH KEY.
# Priority:  CRITICAL (risk score 75.00)
# Resource:  owasp-test
# Project:   62518548529
# Generated: 2026-02-22
# ============================================================
set -euo pipefail

PROJECT="62518548529"
RESOURCE="owasp-test"
CATEGORY="PUBLICLY ACCESSIBLE INSTANCE WITH PROJECT-WIDE SSH KEY."
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
