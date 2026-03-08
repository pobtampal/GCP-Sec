#!/bin/bash
# generate-report.sh - Generate consolidated SAST report from local scan results

set -euo pipefail

REPORT_MD_FILE="reports/sast-summary.md"
REPORT_HTML_FILE="reports/sast-summary.html"
TIMESTAMP=$(date -u +'%Y-%m-%d %H:%M:%S UTC')
COMMIT_SHA=$(git rev-parse --short HEAD 2>/dev/null || echo "unknown")
BRANCH=$(git branch --show-current 2>/dev/null || echo "unknown")
ACTOR=$(git config user.name 2>/dev/null || echo "unknown")

mkdir -p reports

# Generate Markdown report
cat > "$REPORT_MD_FILE" << EOF
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

# Generate HTML report
cat > "$REPORT_HTML_FILE" << EOF
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SAST Security Scan Report</title>
    <style>
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            line-height: 1.6;
            color: #333;
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
            background-color: #f5f5f5;
        }
        .container {
            background-color: white;
            padding: 30px;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }
        h1 {
            color: #2c3e50;
            border-bottom: 3px solid #3498db;
            padding-bottom: 10px;
            margin-bottom: 30px;
        }
        h2 {
            color: #34495e;
            border-bottom: 2px solid #bdc3c7;
            padding-bottom: 5px;
            margin-top: 40px;
            margin-bottom: 20px;
        }
        h3 {
            color: #7f8c8d;
            margin-top: 30px;
        }
        table {
            width: 100%;
            border-collapse: collapse;
            margin: 20px 0;
            background-color: #fff;
        }
        th, td {
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid #ddd;
        }
        th {
            background-color: #f8f9fa;
            font-weight: 600;
            color: #2c3e50;
        }
        tr:hover {
            background-color: #f8f9fa;
        }
        .status-badge {
            display: inline-block;
            padding: 4px 8px;
            border-radius: 4px;
            font-size: 0.9em;
            font-weight: 500;
        }
        .status-run-locally {
            background-color: #3498db;
            color: white;
        }
        .code-block {
            background-color: #f8f9fa;
            border: 1px solid #e9ecef;
            border-radius: 4px;
            padding: 15px;
            font-family: 'Monaco', 'Menlo', 'Ubuntu Mono', monospace;
            font-size: 0.9em;
            margin: 10px 0;
        }
        .metadata {
            background-color: #f8f9fa;
            padding: 20px;
            border-radius: 6px;
            margin: 20px 0;
        }
        .metadata h4 {
            margin-top: 0;
            color: #2c3e50;
        }
        .metadata ul {
            margin: 10px 0;
            padding-left: 20px;
        }
        .metadata li {
            margin: 5px 0;
        }
        .emoji {
            font-size: 1.2em;
        }
        a {
            color: #3498db;
            text-decoration: none;
        }
        a:hover {
            text-decoration: underline;
        }
        .footer {
            margin-top: 40px;
            padding-top: 20px;
            border-top: 1px solid #bdc3c7;
            color: #7f8c8d;
            font-size: 0.9em;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>🔒 SAST Security Scan Report</h1>

        <h2>📊 Summary Table</h2>
        <table>
            <thead>
                <tr>
                    <th>Tool</th>
                    <th>Status</th>
                    <th>Findings</th>
                </tr>
            </thead>
            <tbody>
                <tr>
                    <td><span class="emoji">🔐</span> Gitleaks (Secrets)</td>
                    <td><span class="status-badge status-run-locally">🔍 Run locally</span></td>
                    <td>N/A</td>
                </tr>
                <tr>
                    <td><span class="emoji">🔍</span> Semgrep (Code)</td>
                    <td><span class="status-badge status-run-locally">🔍 Run locally</span></td>
                    <td>N/A</td>
                </tr>
                <tr>
                    <td><span class="emoji">📦</span> govulncheck (Deps)</td>
                    <td><span class="status-badge status-run-locally">🔍 Run locally</span></td>
                    <td>N/A</td>
                </tr>
                <tr>
                    <td><span class="emoji">🐳</span> Trivy (Filesystem)</td>
                    <td><span class="status-badge status-run-locally">🔍 Run locally</span></td>
                    <td>N/A</td>
                </tr>
            </tbody>
        </table>

        <h2>🔬 Detailed Findings</h2>

        <h3>🔐 Gitleaks (Secret Scanning)</h3>
        <p>Run <code>make gitleaks</code> to scan for secrets.</p>

        <h3>🔍 Semgrep (Static Code Analysis)</h3>
        <p>Run <code>make semgrep</code> to perform static analysis.</p>

        <h3>📦 govulncheck (Dependency Vulnerabilities)</h3>
        <p>Run <code>make govulncheck</code> to check for CVEs in dependencies.</p>

        <h3>🐳 Trivy (Container & Filesystem Scan)</h3>
        <p>Run <code>make trivy-fs</code> to scan filesystem for vulnerabilities.</p>

        <div class="metadata">
            <h4>📋 Execution Details</h4>
            <ul>
                <li><strong>Commit:</strong> <a href="https://github.com/wanaware/GCP-Sec/commit/$(git rev-parse HEAD 2>/dev/null || echo "unknown")"><code>$COMMIT_SHA</code></a></li>
                <li><strong>Branch:</strong> <code>$BRANCH</code></li>
                <li><strong>Actor:</strong> $ACTOR</li>
                <li><strong>Timestamp:</strong> $TIMESTAMP</li>
            </ul>

            <h4>🛠️ Local Commands</h4>
            <ul>
                <li>Run all scans: <code>make sast</code></li>
                <li>Generate this report: <code>make report</code></li>
                <li>View individual results: <code>make gitleaks</code>, <code>make semgrep</code>, <code>make govulncheck</code>, <code>make trivy-fs</code></li>
            </ul>
        </div>
    </div>
</body>
</html>
EOF

echo "✅ Reports generated:"
echo "   📄 Markdown: $REPORT_MD_FILE"
echo "   🌐 HTML: $REPORT_HTML_FILE"
echo "💡 Tip: Run 'make sast' to execute all security scans locally"