#!/usr/bin/env bash
# ============================================================
# Finding:   e49bd3ad0e8c962b67ab0f961c7e7daa
# Category:  INSTANCE THAT EXPOSES MANY VALUED RESOURCES
# Priority:  CRITICAL (risk score 75.00)
# Resource:  fleet-manager-integration-test-vm
# Project:   866233621206
# Generated: 2026-02-22
# ============================================================
set -euo pipefail

PROJECT="866233621206"
RESOURCE="fleet-manager-integration-test-vm"
CATEGORY="INSTANCE THAT EXPOSES MANY VALUED RESOURCES"
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
