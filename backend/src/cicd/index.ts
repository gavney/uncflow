import type { Finding } from '../types/findings.ts';

export interface CiCdRunResult {
  status: 'passed' | 'failed';
  exitCode: number;
  totalFindings: number;
  criticalCount: number;
  highCount: number;
  summaryMarkdown: string;
  findings: Finding[];
}

export class CiCdManager {
  /**
   * Generates GitHub Actions workflow YAML configuration
   */
public static generateGitHubWorkflow(
  serverUrl: string = 'http://localhost:3001',
  apiKeyExpr: string = '${{ secrets.UNCFLOW_CI_TOKEN }}'
): string {
  return `name: uncflow Security Gatekeeper

on:
  push:
    branches: [ "main", "master", "develop" ]
  pull_request:
    branches: [ "main", "master" ]

jobs:
  security-audit:
    name: Run uncflow AppSec Audit
    runs-on: ubuntu-latest
    steps:
      - name: Run uncflow Audit via Platform API
        run: |
          echo "Starting uncflow security scan for \${{ github.repository }}..."

          HTTP_CODE=\$(curl -sS -w "%{http_code}" -o audit-result.json \\
            -X POST "${serverUrl}/api/ci/run" \\
            -H "Content-Type: application/json" \\
            -H "Authorization: Bearer ${apiKeyExpr}" \\
            -d '{
              "repo": "\${{ github.repository }}",
              "commitSha": "\${{ github.sha }}",
              "branch": "\${{ github.head_ref || github.ref_name }}",
              "failOnCritical": true
            }')

          echo "HTTP status: \$HTTP_CODE"
          if [ "\$HTTP_CODE" -ne 200 ]; then
            cat audit-result.json
            echo "::error::uncflow API returned HTTP \$HTTP_CODE"
            exit 1
          fi

          node -e 'const r=JSON.parse(require("fs").readFileSync("audit-result.json","utf8")); console.log(r.summaryMarkdown || "")' >> \$GITHUB_STEP_SUMMARY

          EXIT_CODE=\$(node -e 'const r=JSON.parse(require("fs").readFileSync("audit-result.json","utf8")); console.log(r.exitCode ?? 1)')
          TOTAL=\$(node -e 'const r=JSON.parse(require("fs").readFileSync("audit-result.json","utf8")); console.log(r.totalFindings ?? 0)')
          CRITICAL=\$(node -e 'const r=JSON.parse(require("fs").readFileSync("audit-result.json","utf8")); console.log(r.criticalCount ?? 0)')
          HIGH=\$(node -e 'const r=JSON.parse(require("fs").readFileSync("audit-result.json","utf8")); console.log(r.highCount ?? 0)')

          echo "Total findings: \$TOTAL (Critical: \$CRITICAL, High: \$HIGH)"

          if [ "\$EXIT_CODE" -ne 0 ]; then
            echo "::error::uncflow detected blocking vulnerabilities! Build failed."
            exit "\$EXIT_CODE"
          fi

          echo "Security check passed."

      - name: Upload Security Report
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: uncflow-audit-result
          path: audit-result.json
`;
}

  /**
   * Generates GitLab CI configuration YAML
   */
  public static generateGitLabCi(serverUrl: string = 'http://localhost:3001', apiKey: string = 'SECRET_CI_KEY'): string {
    return `stages:
  - test
  - security

ai-security-audit:
  stage: security
  image: node:20-alpine
  script:
    - apk add --no-cache curl
    - |
      RESPONSE=\$(curl -s -X POST "${serverUrl}/api/ci/run" \\
        -H "Content-Type: application/json" \\
        -H "Authorization: Bearer ${apiKey}" \\
        -d '{
          "repo": "\$CI_PROJECT_PATH",
          "commitSha": "\$CI_COMMIT_SHA",
          "branch": "\$CI_COMMIT_REF_NAME",
          "failOnCritical": true
        }')
      echo "\$RESPONSE" > audit-result.json
      node -e '
        const res = JSON.parse(require("fs").readFileSync("audit-result.json", "utf-8"));
        console.log("Findings:", res.totalFindings, "Critical:", res.criticalCount);
        if (res.exitCode !== 0) {
          console.error("Critical security risks detected! Build failed.");
          process.exit(res.exitCode);
        }
      '
  artifacts:
    when: always
    paths:
      - audit-result.json
`;
  }

  /**
   * Formats CI PR comment markdown
   */
  public static formatPrComment(result: CiCdRunResult, commitSha: string): string {
    const icon = result.exitCode === 0 ? '✅' : '🚨';
    const statusText = result.exitCode === 0 ? 'Security Check Passed' : 'Security Vulnerabilities Detected';

    let md = `### ${icon} uncflow: ${statusText}\n\n`;
    md += `**Commit:** \`${commitSha.substring(0, 8)}\` | **Total findings:** **${result.totalFindings}** (Critical: **${result.criticalCount}**, High: **${result.highCount}**)\n\n`;

    if (result.findings.length > 0) {
      md += `| Category | Issue | Location | Severity |\n`;
      md += `| :--- | :--- | :--- | :--- |\n`;
      for (const f of result.findings.slice(0, 10)) {
        const loc = f.category === 'SCA' ? (f as any).artifact : `${f.path}:${(f as any).line}`;
        const id = f.category === 'SCA' ? (f as any).advisoryId : (f as any).class;
        md += `| **${f.category}** | \`${id}\` | \`${loc}\` | **${f.severity || 'MEDIUM'}** |\n`;
      }
      if (result.findings.length > 10) {
        md += `\n*...and ${result.findings.length - 10} more findings in full report.*`;
      }
    } else {
      md += `No security vulnerabilities found in this pull request.\n`;
    }

    return md;
  }
}
