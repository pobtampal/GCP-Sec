# CLAUDE.md — SAST Integration Spec for `gcp-security-analyzer`

This file tells Claude Code exactly what to implement. Work through each section in order. Do not skip sections. Commit after each phase is complete.

---

## Context

**Repository:** `github.com/wanaware/gcp-security-analyzer`
**Language:** Go (module path `github.com/wanaware/gcp-security-analyzer`)
**CI platform:** GitHub Actions (`.github/workflows/ci.yml` already exists)
**Goal:** Integrate four SAST/security scanning tools into the existing CI pipeline, store reports in a GCS bucket, and send email notifications when scans complete.

The existing `ci.yml` has two jobs:
- `test` — runs `go vet`, unit tests, and builds the binary across Go 1.21/1.22/1.23
- `release` — cross-compiles binaries for all platforms on tagged pushes

Do **not** modify or remove any existing steps. Add security scanning as a new parallel job and a new reporting job that runs after it.

---

## Phase 1 — Pre-commit Hook (Gitleaks)

### What to do
Install Gitleaks as a local pre-commit hook so secrets are caught before a commit is ever made.

### Files to create

**`.gitleaks.toml`** — Gitleaks configuration at the repo root:

```toml
title = "gcp-security-analyzer gitleaks config"

[allowlist]
  description = "Global allowlist"
  # Ignore test fixtures and generated coverage data
  paths = [
    "coverage.out",
    "testdata/",
    "findings.csv",
    "findings-report.*",
    "critical-high.csv",
  ]
  # Ignore known-safe placeholder patterns in docs
  regexes = [
    "EXAMPLE_",
    "YOUR_",
  ]

[[rules]]
  id          = "gcp-service-account-key"
  description = "GCP service account private key"
  regex       = '''-----BEGIN (RSA |EC )?PRIVATE KEY-----'''
  severity    = "CRITICAL"
  tags        = ["gcp", "credentials"]

[[rules]]
  id          = "generic-api-key"
  description = "Generic API key assignment"
  regex       = '''(?i)(api[_-]?key|apikey|auth[_-]?token)\s*[:=]\s*["']?[A-Za-z0-9_\-]{20,}["']?'''
  severity    = "HIGH"
  tags        = ["credentials"]
```

**`.github/hooks/pre-commit`** — shell script developers install locally:

```bash
#!/usr/bin/env bash
# Pre-commit hook: run Gitleaks to catch secrets before they are committed.
# Install: cp .github/hooks/pre-commit .git/hooks/pre-commit && chmod +x .git/hooks/pre-commit

set -euo pipefail

if ! command -v gitleaks &> /dev/null; then
  echo "⚠️  gitleaks not found. Install it: https://github.com/gitleaks/gitleaks#installing"
  echo "    Skipping secret scan — install gitleaks to enforce this check locally."
  exit 0
fi

echo "🔍 Running Gitleaks secret scan..."
gitleaks protect --staged --config=.gitleaks.toml --verbose

echo "✅ Gitleaks: no secrets detected."
```

**Update `Makefile`** — add a `setup-hooks` target after the existing `help` target:

```makefile
## setup-hooks: Install pre-commit security hooks
setup-hooks:
	@cp .github/hooks/pre-commit .git/hooks/pre-commit
	@chmod +x .git/hooks/pre-commit
	@echo "✓ Pre-commit hook installed. Run 'make setup-hooks' on each clone."
```

Also add a `sast` target that developers can run locally:

```makefile
## sast: Run all SAST checks locally (requires gitleaks, semgrep, govulncheck, trivy)
sast:
	@echo "=== Gitleaks ===" && gitleaks detect --config=.gitleaks.toml --verbose || true
	@echo "=== Semgrep ===" && semgrep --config=.semgrep.yml --error . || true
	@echo "=== govulncheck ===" && govulncheck ./... || true
	@echo "=== Trivy (filesystem) ===" && trivy fs --severity HIGH,CRITICAL . || true
```

---

## Phase 2 — Semgrep Rules File

### What to do
Create a Semgrep configuration that targets Go-specific vulnerability patterns relevant to this codebase.

### File to create

**`.semgrep.yml`** at the repo root:

```yaml
# Semgrep configuration for gcp-security-analyzer
# Docs: https://semgrep.dev/docs/running-rules/

rules:
  # ── Credentials & secrets ─────────────────────────────────────────
  - id: hardcoded-gcp-credential
    patterns:
      - pattern: |
          $X := "$Y"
      - metavariable-regex:
          metavariable: $Y
          regex: "AIza[0-9A-Za-z\\-_]{35}"
    message: >
      Hardcoded GCP API key detected in $X. Move this value to an
      environment variable or Secret Manager.
    severity: ERROR
    languages: [go]
    metadata:
      cwe: "CWE-798"
      owasp: "A02:2021"

  - id: hardcoded-private-key-string
    pattern: |
      $X = "-----BEGIN RSA PRIVATE KEY-----..."
    message: >
      Hardcoded private key string. Use os.Getenv or load from a
      secrets manager at runtime.
    severity: ERROR
    languages: [go]
    metadata:
      cwe: "CWE-321"

  # ── Cryptographic weaknesses ──────────────────────────────────────
  - id: weak-hash-md5
    pattern: md5.New()
    message: >
      MD5 is cryptographically broken. Use sha256.New() or sha512.New()
      for integrity checks, or bcrypt/argon2 for password hashing.
    severity: WARNING
    languages: [go]
    metadata:
      cwe: "CWE-327"
      owasp: "A02:2021"

  - id: weak-hash-sha1
    pattern: sha1.New()
    message: >
      SHA-1 is deprecated for security use. Prefer SHA-256 or SHA-512.
    severity: WARNING
    languages: [go]
    metadata:
      cwe: "CWE-327"

  # ── Command injection ─────────────────────────────────────────────
  - id: exec-command-injection
    patterns:
      - pattern: exec.Command($CMD, ..., $ARG, ...)
      - pattern-not: exec.Command("...", ...)
    message: >
      exec.Command called with a non-literal command or argument.
      If $CMD or $ARG comes from user input or external data, this
      is a command injection vulnerability.
    severity: ERROR
    languages: [go]
    metadata:
      cwe: "CWE-78"
      owasp: "A03:2021"

  # ── HTTP / TLS misconfigurations ──────────────────────────────────
  - id: tls-insecure-skip-verify
    pattern: |
      tls.Config{..., InsecureSkipVerify: true, ...}
    message: >
      InsecureSkipVerify disables TLS certificate validation.
      Remove this flag in production code.
    severity: ERROR
    languages: [go]
    metadata:
      cwe: "CWE-295"
      owasp: "A02:2021"

  - id: http-server-no-timeout
    pattern: |
      http.ListenAndServe($ADDR, $HANDLER)
    message: >
      http.ListenAndServe has no read/write timeouts. Use an
      http.Server struct with explicit ReadTimeout and WriteTimeout
      to prevent slowloris-style attacks.
    severity: WARNING
    languages: [go]
    metadata:
      cwe: "CWE-400"

  # ── Sensitive data in logs ────────────────────────────────────────
  - id: log-sensitive-field
    patterns:
      - pattern: log.$FUNC(..., $VAR, ...)
      - metavariable-regex:
          metavariable: $VAR
          regex: "(?i)(password|secret|token|key|credential)"
    message: >
      A variable with a sensitive-sounding name ($VAR) is being
      logged. Ensure this does not contain secret material.
    severity: WARNING
    languages: [go]
    metadata:
      cwe: "CWE-532"
      owasp: "A09:2021"

  # ── File path traversal ───────────────────────────────────────────
  - id: path-traversal-filepath-join
    patterns:
      - pattern: filepath.Join($BASE, $INPUT)
      - pattern-not: filepath.Join("...", "...")
    message: >
      filepath.Join with a non-literal second argument may allow
      path traversal if $INPUT comes from external data. Validate
      and clean the path before use.
    severity: WARNING
    languages: [go]
    metadata:
      cwe: "CWE-22"
      owasp: "A01:2021"
```

---

## Phase 3 — GitHub Actions: SAST Workflow

### What to do
Create a new workflow file that runs all four security scans. This workflow is **separate** from the existing `ci.yml` so it can run in parallel without blocking the existing test matrix.

### File to create

**`.github/workflows/sast.yml`**:

```yaml
name: SAST Security Scans

on:
  push:
    branches: [main, master]
  pull_request:
    branches: [main, master]

permissions:
  contents: read
  security-events: write   # Required to upload SARIF to GitHub Security tab

env:
  GO_VERSION: "1.23"
  REPORT_DIR: /tmp/sast-reports

jobs:
  # ─── Job 1: Secret Scanning (Gitleaks) ───────────────────────────
  gitleaks:
    name: Secret Scan (Gitleaks)
    runs-on: ubuntu-latest
    steps:
      - name: Checkout
        uses: actions/checkout@v4
        with:
          fetch-depth: 0   # Full history so Gitleaks can scan all commits

      - name: Run Gitleaks
        uses: gitleaks/gitleaks-action@v2
        with:
          config-path: .gitleaks.toml
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
          GITLEAKS_LICENSE: ${{ secrets.GITLEAKS_LICENSE }}   # Only needed for org-level scanning; omit for public repos

      - name: Upload Gitleaks SARIF
        if: always()
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: results.sarif
          category: gitleaks

  # ─── Job 2: Static Code Analysis (Semgrep) ───────────────────────
  semgrep:
    name: Code Scan (Semgrep)
    runs-on: ubuntu-latest
    container:
      image: semgrep/semgrep
    steps:
      - name: Checkout
        uses: actions/checkout@v4

      - name: Create report directory
        run: mkdir -p ${{ env.REPORT_DIR }}

      - name: Run Semgrep — custom rules
        run: |
          semgrep \
            --config=.semgrep.yml \
            --config=p/golang \
            --config=p/owasp-top-ten \
            --severity=ERROR \
            --sarif \
            --output=${{ env.REPORT_DIR }}/semgrep-report.sarif \
            --error \
            .
        continue-on-error: false

      - name: Upload Semgrep SARIF to GitHub Security
        if: always()
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: ${{ env.REPORT_DIR }}/semgrep-report.sarif
          category: semgrep

      - name: Upload Semgrep report artifact
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: semgrep-report
          path: ${{ env.REPORT_DIR }}/semgrep-report.sarif
          retention-days: 90

  # ─── Job 3: Dependency Vulnerability Scan (govulncheck) ──────────
  govulncheck:
    name: Dependency Scan (govulncheck)
    runs-on: ubuntu-latest
    steps:
      - name: Checkout
        uses: actions/checkout@v4

      - name: Set up Go
        uses: actions/setup-go@v5
        with:
          go-version: ${{ env.GO_VERSION }}
          cache: true

      - name: Install govulncheck
        run: go install golang.org/x/vuln/cmd/govulncheck@latest

      - name: Create report directory
        run: mkdir -p ${{ env.REPORT_DIR }}

      - name: Run govulncheck
        run: |
          govulncheck -json ./... \
            > ${{ env.REPORT_DIR }}/govulncheck-report.json
          # Also run in human-readable mode for the log
          govulncheck ./...

      - name: Upload govulncheck report artifact
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: govulncheck-report
          path: ${{ env.REPORT_DIR }}/govulncheck-report.json
          retention-days: 90

  # ─── Job 4: Container / Filesystem Scan (Trivy) ──────────────────
  trivy:
    name: Container Scan (Trivy)
    runs-on: ubuntu-latest
    steps:
      - name: Checkout
        uses: actions/checkout@v4

      - name: Set up Go
        uses: actions/setup-go@v5
        with:
          go-version: ${{ env.GO_VERSION }}
          cache: true

      - name: Build binary (for filesystem scan)
        run: go build -o gcp-security-analyzer .

      - name: Create report directory
        run: mkdir -p ${{ env.REPORT_DIR }}

      - name: Run Trivy filesystem scan
        uses: aquasecurity/trivy-action@master
        with:
          scan-type: fs
          scan-ref: .
          format: sarif
          output: ${{ env.REPORT_DIR }}/trivy-report.sarif
          severity: HIGH,CRITICAL
          exit-code: "1"
          ignore-unfixed: false

      - name: Upload Trivy SARIF to GitHub Security
        if: always()
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: ${{ env.REPORT_DIR }}/trivy-report.sarif
          category: trivy

      - name: Upload Trivy report artifact
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: trivy-report
          path: ${{ env.REPORT_DIR }}/trivy-report.sarif
          retention-days: 90

  # ─── Job 5: Upload Reports to GCS + Notify ───────────────────────
  report-and-notify:
    name: Upload Reports & Notify
    runs-on: ubuntu-latest
    needs: [gitleaks, semgrep, govulncheck, trivy]
    # Run this job even when scans fail so reports are always uploaded
    if: always()
    steps:
      - name: Download all scan artifacts
        uses: actions/download-artifact@v4
        with:
          path: /tmp/sast-reports

      - name: Authenticate to GCP
        uses: google-github-actions/auth@v2
        with:
          credentials_json: ${{ secrets.GCP_SA_KEY }}

      - name: Upload reports to GCS
        uses: google-github-actions/upload-cloud-storage@v2
        with:
          path: /tmp/sast-reports
          destination: >-
            ${{ secrets.SAST_REPORT_BUCKET }}/${{
              github.event.pull_request.head.sha || github.sha
            }}
          parent: false

      - name: Compute overall scan status
        id: status
        run: |
          GITLEAKS="${{ needs.gitleaks.result }}"
          SEMGREP="${{ needs.semgrep.result }}"
          GOVULN="${{ needs.govulncheck.result }}"
          TRIVY="${{ needs.trivy.result }}"

          if [[ "$GITLEAKS" == "success" && "$SEMGREP" == "success" \
             && "$GOVULN" == "success" && "$TRIVY" == "success" ]]; then
            echo "overall=PASSED" >> "$GITHUB_OUTPUT"
            echo "emoji=✅" >> "$GITHUB_OUTPUT"
          else
            echo "overall=FAILED" >> "$GITHUB_OUTPUT"
            echo "emoji=⛔" >> "$GITHUB_OUTPUT"
          fi

      - name: Send email notification
        uses: dawidd6/action-send-mail@v3
        with:
          server_address: smtp.sendgrid.net
          server_port: 465
          username: apikey
          password: ${{ secrets.SENDGRID_API_KEY }}
          to: ${{ secrets.SECURITY_NOTIFY_EMAIL }}
          from: ci@wanaware.com
          subject: >-
            ${{ steps.status.outputs.emoji }} SAST ${{
              steps.status.outputs.overall }} — ${{
              github.ref_name }} (${{ github.sha &&
              github.sha[:7] || 'unknown' }})
          body: |
            Security scan completed for gcp-security-analyzer.

            Branch : ${{ github.ref_name }}
            Commit : ${{ github.sha }}
            Actor  : ${{ github.actor }}
            Status : ${{ steps.status.outputs.overall }}

            Individual check results:
              Gitleaks (secrets)        : ${{ needs.gitleaks.result }}
              Semgrep (code analysis)   : ${{ needs.semgrep.result }}
              govulncheck (deps)        : ${{ needs.govulncheck.result }}
              Trivy (filesystem/deps)   : ${{ needs.trivy.result }}

            GitHub Security tab (SARIF findings):
            https://github.com/${{ github.repository }}/security/code-scanning

            Full reports in GCS:
            https://storage.googleapis.com/${{ secrets.SAST_REPORT_BUCKET }}/${{ github.sha }}/

            Workflow run:
            https://github.com/${{ github.repository }}/actions/runs/${{ github.run_id }}
```

---

## Phase 4 — GCS Bucket Setup

The report bucket must be provisioned once before the workflow runs. Claude Code should run these commands as a one-time setup step when the GCP project is available.

```bash
# ── 1. Create the bucket ──────────────────────────────────────────────────
GCP_PROJECT="wanaware-prod"          # Change to actual project ID
BUCKET="wanaware-sast-reports"       # Must be globally unique
REGION="us-central1"

gsutil mb -l "$REGION" -p "$GCP_PROJECT" "gs://$BUCKET"

# ── 2. Enable versioning (protects against accidental overwrites) ──────────
gsutil versioning set on "gs://$BUCKET"

# ── 3. Lifecycle policy: auto-delete reports older than 365 days ──────────
cat > /tmp/lifecycle.json << 'EOF'
{
  "lifecycle": {
    "rule": [{
      "action": { "type": "Delete" },
      "condition": { "age": 365 }
    }]
  }
}
EOF
gsutil lifecycle set /tmp/lifecycle.json "gs://$BUCKET"

# ── 4. Lock down public access ────────────────────────────────────────────
gsutil iam ch -d allUsers "gs://$BUCKET" 2>/dev/null || true

# ── 5. Grant the GitHub Actions service account write access ─────────────
#    (Replace with the actual service account used for GCP_SA_KEY)
SA_EMAIL="github-actions@${GCP_PROJECT}.iam.gserviceaccount.com"
gsutil iam ch "serviceAccount:${SA_EMAIL}:objectAdmin" "gs://$BUCKET"

echo "Bucket gs://$BUCKET is ready."
```

The service account must also have the `storage.objects.create` and `storage.objects.get` IAM permissions. The minimum role is `roles/storage.objectAdmin` scoped to this bucket.

---

## Phase 5 — GitHub Secrets

Add these secrets to **Settings → Secrets and variables → Actions** in the repository before running the workflow for the first time:

| Secret name             | Value                                                                 |
|-------------------------|-----------------------------------------------------------------------|
| `GCP_SA_KEY`            | JSON key for a GCP service account with `objectAdmin` on the bucket  |
| `SAST_REPORT_BUCKET`    | GCS bucket name, e.g. `wanaware-sast-reports`                        |
| `SENDGRID_API_KEY`      | SendGrid API key for outbound email                                   |
| `SECURITY_NOTIFY_EMAIL` | Recipient address, e.g. `security@wanaware.com`                      |
| `GITLEAKS_LICENSE`      | Gitleaks commercial license key (only required for private org repos) |

---

## Phase 6 — Makefile and README Updates

### Makefile additions

Append these targets to the existing `Makefile` (after the `help` target):

```makefile
## govulncheck: Scan Go dependencies for known CVEs
govulncheck:
	@which govulncheck > /dev/null 2>&1 || go install golang.org/x/vuln/cmd/govulncheck@latest
	govulncheck ./...

## trivy-fs: Scan the filesystem for vulnerabilities (requires trivy)
trivy-fs:
	@which trivy > /dev/null 2>&1 || (echo "Install trivy: https://aquasecurity.github.io/trivy/"; exit 1)
	trivy fs --severity HIGH,CRITICAL .

## gitleaks: Scan the full repo history for leaked secrets
gitleaks:
	@which gitleaks > /dev/null 2>&1 || (echo "Install gitleaks: https://github.com/gitleaks/gitleaks"; exit 1)
	gitleaks detect --config=.gitleaks.toml --verbose

## semgrep: Run Semgrep static analysis
semgrep:
	@which semgrep > /dev/null 2>&1 || (echo "Install semgrep: pip install semgrep"; exit 1)
	semgrep --config=.semgrep.yml --config=p/golang --severity=ERROR --error .
```

### README additions

Add a new **Security** section to `README.md` after the existing **Usage** section:

```markdown
## Security

This repository integrates four automated SAST checks that run on every push and pull request via GitHub Actions (`.github/workflows/sast.yml`).

| Check | Tool | What it catches |
|---|---|---|
| Secret scanning | Gitleaks | Hardcoded API keys, private keys, GCP credentials |
| Static code analysis | Semgrep | Injection flaws, TLS misconfigs, sensitive data in logs |
| Dependency CVEs | govulncheck | Known CVEs in Go module dependencies |
| Filesystem / dep scan | Trivy | CVEs in Go dependencies and OS packages |

Findings appear in the **Security → Code scanning** tab of this repository. Full JSON/SARIF reports for every build are stored in the GCS bucket configured via `SAST_REPORT_BUCKET`.

### Running scans locally

```bash
# Install hooks (run once per clone)
make setup-hooks

# Run all SAST tools
make sast

# Run individual tools
make gitleaks
make semgrep
make govulncheck
make trivy-fs
```

To install the required tools:

```bash
brew install gitleaks trivy          # macOS
pip install semgrep                  # all platforms
go install golang.org/x/vuln/cmd/govulncheck@latest
```
```

---

## Phase 7 — `.gitignore` Updates

Ensure generated report files and test artifacts are not accidentally committed. Append these lines to `.gitignore` (create the file if it does not exist):

```gitignore
# SAST report output
*.sarif
*-report.json
*-report.sarif
gitleaks-report.*

# Local scan results
/tmp/sast-reports/

# Trivy cache
.trivy/

# Semgrep cache
.semgrep/
```

---

## Implementation Order

Execute the phases in this sequence:

1. **Phase 2** — Create `.semgrep.yml` (no dependencies)
2. **Phase 1** — Create `.gitleaks.toml` and `.github/hooks/pre-commit`; update `Makefile`
3. **Phase 7** — Update `.gitignore`
4. **Phase 3** — Create `.github/workflows/sast.yml`
5. **Phase 5** — Add GitHub Secrets (manual step — prompt the user to do this)
6. **Phase 4** — Provision GCS bucket (manual step — prompt the user to run the commands)
7. **Phase 6** — Update `Makefile` targets and `README.md`

---

## Acceptance Criteria

The implementation is complete when all of the following are true:

- [ ] `.gitleaks.toml` exists at repo root and `gitleaks detect --config=.gitleaks.toml .` exits 0 on the clean repo
- [ ] `.github/hooks/pre-commit` exists and is executable
- [ ] `.semgrep.yml` exists and `semgrep --config=.semgrep.yml --dry-run .` produces no parse errors
- [ ] `.github/workflows/sast.yml` passes YAML validation (`yamllint .github/workflows/sast.yml`)
- [ ] All four SAST jobs appear in the **Actions** tab on the next push to `main`
- [ ] SARIF results appear in **Security → Code scanning** after the first successful run
- [ ] Reports are written to `gs://<SAST_REPORT_BUCKET>/<commit-sha>/` after the first successful run
- [ ] A notification email is received at `SECURITY_NOTIFY_EMAIL` after the first run (pass or fail)
- [ ] The existing `ci.yml` `test` and `release` jobs are unchanged and still pass
- [ ] `make sast` runs all four tools locally without errors when the tools are installed

---

## Tool Version Pins

Pin these versions to ensure reproducible scans:

| Tool | Pinned version | How to update |
|---|---|---|
| `gitleaks/gitleaks-action` | `v2` | Bump in `sast.yml` |
| `semgrep/semgrep` container | `latest` (use `semgrep/semgrep:1.x.y` to pin) | Update image tag |
| `govulncheck` | `latest` via `go install` | Pin with `@vX.Y.Z` |
| `aquasecurity/trivy-action` | `master` (use `@vX.Y.Z` to pin) | Update action ref |
| `dawidd6/action-send-mail` | `v3` | Bump in `sast.yml` |

---

## Notes for Claude Code

- When creating `.github/workflows/sast.yml`, verify that the `permissions` block at the top-level includes `security-events: write`. Without this, SARIF upload steps will fail silently.
- The `gitleaks-action@v2` step creates a file called `results.sarif` in the workspace root by default. The upload-sarif step references this path directly.
- `govulncheck` exits non-zero when vulnerabilities are found. This is the intended behaviour — the job should fail and block merge.
- The `report-and-notify` job uses `if: always()` so reports are uploaded and notifications sent even when a scan job fails.
- Do not add `GITLEAKS_LICENSE` to the workflow `env` block — it must remain a secret and be passed only via `env` inside the specific step that uses it.
- The Semgrep `p/golang` ruleset covers Go-specific issues beyond the custom `.semgrep.yml` rules (memory safety, goroutine leaks, unsafe pointer usage). Both configs should always be passed together.
