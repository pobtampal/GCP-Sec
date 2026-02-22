#!/usr/bin/env bash
# ============================================================
# Finding:   b829066db896ade15ee4c3023f74f848
# Category:  SOFTWARE_VULNERABILITY
# Priority:  CRITICAL (risk score 94.08)
# Resource:  wanaware-deployment-cluster
# Project:   503291607878
# CVE:           CVE-2023-24540 (CVSS 9.8)
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
