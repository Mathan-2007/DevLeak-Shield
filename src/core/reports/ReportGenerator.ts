import { ReportPayload, ReportSummary, SecretFinding, PolicyRule } from "../../types";

export class ReportGenerator {
  generateJson(findings: SecretFinding[], policyRules: PolicyRule[]): string {
    const summary = this.buildSummary(findings);
    const payload: ReportPayload = {
      summary,
      findings,
      policyRules,
    };
    return JSON.stringify(payload, null, 2);
  }

  generateHtml(findings: SecretFinding[], policyRules: PolicyRule[]): string {
    const summary = this.buildSummary(findings);
    const rows = findings
      .map((finding) => `
        <tr>
          <td>${finding.category}</td>
          <td>${finding.value}</td>
          <td>${finding.detection.risk}</td>
          <td>${finding.detection.confidence}</td>
          <td>${finding.location.filePath ?? "clipboard"}</td>
        </tr>
      `)
      .join("\n");

    return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <title>DevLeakShield Security Report</title>
  <style>
    body { font-family: Arial, sans-serif; margin: 24px; }
    table { border-collapse: collapse; width: 100%; }
    th, td { border: 1px solid #ddd; padding: 8px; }
    th { background: #222; color: #fff; }
  </style>
</head>
<body>
  <h1>DevLeakShield Security Report</h1>
  <p>Generated: ${summary.generatedAt}</p>
  <p>Findings: ${summary.totalFindings}</p>
  <p>Workspace Security Score: ${summary.score}</p>
  <table>
    <thead>
      <tr><th>Category</th><th>Value</th><th>Risk</th><th>Confidence</th><th>Location</th></tr>
    </thead>
    <tbody>${rows}</tbody>
  </table>
</body>
</html>`;
  }

  private buildSummary(findings: SecretFinding[]): ReportSummary {
    const riskDistribution = findings.reduce<Record<string, number>>((acc, finding) => {
      acc[finding.category] = (acc[finding.category] ?? 0) + 1;
      return acc;
    }, {});

    const score = findings.length === 0
      ? 100
      : Number((100 - Math.min(100, findings.reduce((sum, item) => sum + item.detection.risk * 100, 0) / findings.length)).toFixed(2));

    return {
      totalFindings: findings.length,
      riskDistribution,
      score,
      generatedAt: new Date().toISOString(),
    };
  }
}
