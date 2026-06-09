import { ReportSummary, SecretFinding } from "../../types";

export class SecurityDashboardService {
  private history: ReportSummary[] = [];

  recordSummary(summary: ReportSummary): void {
    this.history.push(summary);
    if (this.history.length > 100) {
      this.history.shift();
    }
  }

  getCurrentScore(): number {
    if (this.history.length === 0) return 100;
    return Number(
      (
        this.history[this.history.length - 1].score
      ).toFixed(2)
    );
  }

  getRiskDistribution(): Record<string, number> {
    const distribution: Record<string, number> = {};
    this.history.forEach((summary) => {
      Object.entries(summary.riskDistribution).forEach(([category, count]) => {
        distribution[category] = (distribution[category] ?? 0) + count;
      });
    });
    return distribution;
  }

  getHistoricalAnalytics(): ReportSummary[] {
    return [...this.history];
  }

  static buildSummary(findings: SecretFinding[]): ReportSummary {
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
