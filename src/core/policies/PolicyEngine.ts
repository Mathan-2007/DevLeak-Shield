import { PolicyDecision, PolicyRule, SecretFinding } from "../../types";

export class PolicyEngine {
  constructor(private readonly rules: PolicyRule[] = []) {}

  evaluate(findings: SecretFinding[]): PolicyDecision {
    if (this.rules.length === 0) {
      return {
        allowed: true,
        reason: "No enterprise policy configured.",
        risk: this.averageRisk(findings),
      };
    }

    const violation = this.rules.find((rule) => {
      if (!rule.enabled) return false;
      const matches = findings.filter((finding) =>
        rule.categories.includes(finding.category)
      );
      const ruleRisk = matches.reduce((score, finding) => score + finding.detection.risk, 0) / Math.max(1, matches.length);
      return ruleRisk >= rule.threshold;
    });

    if (violation) {
      return {
        allowed: false,
        reason: `Policy violation: ${violation.name} exceeded risk threshold ${violation.threshold}.`,
        ruleId: violation.id,
        risk: this.averageRisk(findings),
      };
    }

    return {
      allowed: true,
      reason: "All configured policies passed.",
      risk: this.averageRisk(findings),
    };
  }

  createRule(rule: PolicyRule): void {
    this.rules.push(rule);
  }

  getRules(): PolicyRule[] {
    return [...this.rules];
  }

  private averageRisk(findings: SecretFinding[]): number {
    if (findings.length === 0) return 0;
    return Number(
      (
        findings.reduce((sum, item) => sum + item.detection.risk, 0) / findings.length
      ).toFixed(2)
    );
  }
}