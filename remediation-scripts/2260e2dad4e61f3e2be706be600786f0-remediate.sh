#!/usr/bin/env bash
# ============================================================
# Finding:   2260e2dad4e61f3e2be706be600786f0
# Category:  SOFTWARE_VULNERABILITY
# Priority:  CRITICAL (risk score 91.56)
# Resource:  gke-wanaware-deploym-primary-node-poo-26baa5e5-w8uh
# Project:   503291607878
# CVE:           CVE-2025-22871 (CVSS 9.1)
# Generated: 2026-02-22
# ============================================================
set -euo pipefail

PROJECT="503291607878"
RESOURCE="gke-wanaware-deploym-primary-node-poo-26baa5e5-w8uh"
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
