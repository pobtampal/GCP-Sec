#!/bin/bash
# generate-report.sh - Generate consolidated SAST report from local scan results

set -euo pipefail

REPORT_FILE="reports/sast-summary.md"
TIMESTAMP=$(date -u +'%Y-%m-%d %H:%M:%S UTC')
COMMIT_SHA=$(git rev-parse --short HEAD 2>/dev/null || echo "unknown")
BRANCH=$(git branch --show-current 2>/dev/null || echo "unknown")
ACTOR=$(git config user.name 2>/dev/null || echo "unknown")

mkdir -p reports

cat > "$REPORT_FILE" << EOF
# SAST Security Scan Report

## Summary Table

| Tool | Status | Findings |
|------|--------|----------|
| Gitleaks (Secrets) | 🔍 Run locally | N/A |
| Semgrep (Code) | 🔍 Run locally | N/A |
| govulncheck (Deps) | 🔍 Run locally | N/A |
| Trivy (Filesystem) | 🔍 Run locally | N/A |

---

## Detailed Findings

### 🔐 Gitleaks (Secret Scanning)

Run \`make gitleaks\` to scan for secrets.

### 🔍 Semgrep (Static Code Analysis)

Run \`make semgrep\` to perform static analysis.

### 📦 govulncheck (Dependency Vulnerabilities)

Run \`make govulncheck\` to check for CVEs in dependencies.

### 🐳 Trivy (Container & Filesystem Scan)

Run \`make trivy-fs\` to scan filesystem for vulnerabilities.

---

## Metadata & Links

**Execution Details**
- Commit: [\`$COMMIT_SHA\`](https://github.com/wanaware/GCP-Sec/commit/$(git rev-parse HEAD 2>/dev/null || echo "unknown"))
- Branch: \`$BRANCH\`
- Actor: $ACTOR
- Timestamp: $TIMESTAMP

**Local Commands**
- Run all scans: \`make sast\`
- Generate this report: \`make report\`
- View individual results: \`make gitleaks\`, \`make semgrep\`, \`make govulncheck\`, \`make trivy-fs\`

EOF

echo "✅ Report generated: $REPORT_FILE"
echo "💡 Tip: Run 'make sast' to execute all security scans locally"