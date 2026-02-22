#!/usr/bin/env bash
# ============================================================
# Finding:   138bc5685c201b2db4585adbe40021d3
# Category:  SOFTWARE_VULNERABILITY
# Priority:  CRITICAL (risk score 77.76)
# Resource:  wanaware-deployment-cluster
# Project:   503291607878
# CVE:           CVE-2025-4674 (CVSS 8.6)
# Generated: 2026-02-22
# ============================================================
set -euo pipefail

PROJECT="503291607878"
RESOURCE="wanaware-deployment-cluster"
CATEGORY="SOFTWARE_VULNERABILITY"
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
