#!/usr/bin/env python3
# ============================================================
# Finding:   9f0e8d1d0a674ea986fc4822dbd09100
# Category:  CONTAINER_IMAGE_VULNERABILITY
# Priority:  CRITICAL (risk score 83.28)
# Resource:  projects/wanaware-security-map-dev/locations/us-central1/repositories/security-app/dockerImages/security-app@sha256:0810e0325b8319f74a3643d74dd142ffad277da4f1f664858133904380838ae0
# Project:   62518548529
# CVE:           CVE-2026-23950 (CVSS 8.8)
# Generated: 2026-02-22
# ============================================================

import subprocess
import sys
import json

PROJECT  = "wanaware-security-map-dev"
CLUSTER  = "UNKNOWN_CLUSTER"
ZONE     = "UNKNOWN_ZONE"
POD_NAME = "projects/wanaware-security-map-dev/locations/us-central1/repositories/security-app/dockerImages/security-app@sha256:0810e0325b8319f74a3643d74dd142ffad277da4f1f664858133904380838ae0"
CVE_ID   = "CVE-2026-23950"
CVSS     = 8.8
DRY_RUN  = False  # set to True to skip cluster authentication

def run(cmd, capture=True, check=True):
    print(f"[CMD] {' '.join(cmd)}")
    result = subprocess.run(cmd, capture_output=capture, text=True)
    if check and result.returncode != 0:
        print(f"[ERROR] {result.stderr.strip()}", file=sys.stderr)
        sys.exit(1)
    return result.stdout.strip() if capture else ""

def main():
    print(f"[INFO] Container vulnerability: {CVE_ID} (CVSS {CVSS})")
    print(f"[INFO] Pod: {POD_NAME}  Cluster: {CLUSTER}  Zone: {ZONE}  Project: {PROJECT}")
    print()

    # Step 1: Query Container Analysis API
    print("[INFO] Checking Container Analysis for vulnerability occurrences...")
    try:
        out = run([
            "gcloud", "artifacts", "vulnerabilities", "list-occurrences",
            "--project", PROJECT, "--format", "json",
            "--filter", f"vulnerability.cveId={CVE_ID}",
        ], check=False)
        occurrences = json.loads(out) if out else []
        if occurrences:
            print(f"[INFO] Found {len(occurrences)} affected image(s):")
            for occ in occurrences[:5]:
                print(f"  - {occ.get('resourceUri', 'unknown')}")
        else:
            print(f"[INFO] No Container Analysis occurrences for {CVE_ID}.")
    except Exception as e:
        print(f"[WARN] Could not query Container Analysis: {e}")
    print()

    # Step 2: Get cluster credentials and inspect pod
    if not DRY_RUN:
        print(f"[INFO] Getting credentials for cluster {CLUSTER}...")
        run(["gcloud", "container", "clusters", "get-credentials",
             CLUSTER, "--zone", ZONE, "--project", PROJECT], capture=False)

        print(f"[INFO] Checking images in pod {POD_NAME}...")
        try:
            pod_json = run(["kubectl", "get", "pod", POD_NAME, "-o", "json"])
            pod = json.loads(pod_json)
            for c in pod.get("spec", {}).get("containers", []):
                print(f"  Container: {c['name']}  Image: {c.get('image', 'unknown')}")
        except Exception as e:
            print(f"[WARN] Could not inspect pod: {e}")
        print()

    # Step 3: Remediation steps
    print(f"""[ACTION REQUIRED] Remediate {CVE_ID}:

1. Update the Dockerfile to use a patched base image.
2. Rebuild and push the new image:
       docker build -t gcr.io/{PROJECT}/<image-name>:<new-tag> .
       docker push gcr.io/{PROJECT}/<image-name>:<new-tag>
3. Update the Kubernetes deployment:
       kubectl set image deployment/<DEPLOYMENT> <CONTAINER>=gcr.io/{PROJECT}/<image-name>:<new-tag>
4. Verify the fix:
       gcloud artifacts vulnerabilities scan gcr.io/{PROJECT}/<image-name>:<new-tag>
""")

if __name__ == "__main__":
    main()
