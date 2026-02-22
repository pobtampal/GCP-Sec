#!/usr/bin/env python3
# ============================================================
# Finding:   76a35c8f7d844b9c0695a1fd3fd9c969
# Category:  OS_VULNERABILITY
# Priority:  CRITICAL (risk score 77.76)
# Resource:  cluster-1
# Project:   45062729948
# CVE:           CVE-2021-3517 (CVSS 8.6)
# Generated: 2026-02-22
# ============================================================

import subprocess
import sys
import json

PROJECT  = "wanaware-dev"
INSTANCE = "cluster-1"
ZONE     = "us-central1-a"
CVE_ID   = "CVE-2021-3517"
DRY_RUN  = False

def run(cmd, capture=True, check=True):
    print(f"[CMD] {' '.join(cmd)}")
    result = subprocess.run(cmd, capture_output=capture, text=True)
    if check and result.returncode != 0:
        print(f"[ERROR] {result.stderr.strip()}", file=sys.stderr)
        sys.exit(1)
    return result.stdout.strip() if capture else ""

def main():
    print(f"[INFO] OS vulnerability: {CVE_ID}")
    print(f"[INFO] Instance: {INSTANCE}  Zone: {ZONE}  Project: {PROJECT}")
    print()

    # Step 1: Check OS Config vulnerability report
    print("[INFO] Querying OS Config vulnerability report...")
    try:
        report_json = run([
            "gcloud", "compute", "os-config", "vulnerability-reports", "get",
            INSTANCE, "--zone", ZONE, "--project", PROJECT, "--format", "json",
        ], check=False)
        report = json.loads(report_json) if report_json else {}
        vulns = report.get("vulnerabilities", [])
        matching = [v for v in vulns if CVE_ID in str(v.get("cveId", ""))]
        if matching:
            for v in matching[:3]:
                print(f"  Package: {v.get('packageName')}  "
                      f"Installed: {v.get('installedVersion')}  "
                      f"Fixed in: {v.get('fixedVersion', 'N/A')}")
        else:
            print(f"[INFO] {CVE_ID} not in OS Config report (agent may not be installed).")
    except Exception as e:
        print(f"[WARN] Could not parse OS Config report: {e}")
    print()

    # Step 2: Patch job command
    patch_cmd = [
        "gcloud", "compute", "os-config", "patch-jobs", "execute",
        f"--project={PROJECT}",
        f"--instance-filter-names=zones/{ZONE}/instances/{INSTANCE}",
        "--apt-upgrades-type=stable",
        f"--description=Remediate {CVE_ID}",
    ]
    print("[INFO] Patch command:")
    print("  " + " \\\n  ".join(patch_cmd))
    print()

    if DRY_RUN:
        print("[DRY-RUN] Skipping patch execution.")
        return

    answer = input("Run patch job now? [y/N]: ").strip().lower()
    if answer == "y":
        run(patch_cmd, capture=False)
        print(f"[OK] Patch job launched. Monitor: gcloud compute os-config patch-jobs list --project={PROJECT}")
    else:
        print("[INFO] Skipped. Run the patch command above manually when ready.")

if __name__ == "__main__":
    main()
