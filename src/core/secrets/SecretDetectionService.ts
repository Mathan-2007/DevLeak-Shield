import { SecretClassifier } from "./SecretClassifier";
import { SecretFinding, DetectionResult } from "../../types";

const REGEX_RULES: Array<{ name: string; pattern: RegExp; category: string }> = [
  { name: "openai", pattern: /sk-[A-Za-z0-9]{10,}/, category: "openai" },
  { name: "aws", pattern: /AKIA[0-9A-Z]{16}/, category: "aws" },
  { name: "github", pattern: /ghp_[A-Za-z0-9]{36}/, category: "github" },
  { name: "jwt", pattern: /[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+/, category: "jwt" },
  { name: "ssh", pattern: /-----BEGIN (RSA|OPENSSH|DSA|EC) PRIVATE KEY-----/, category: "ssh" },
  { name: "database", pattern: /(postgres|mongodb|mysql|sqlserver).*(password|pwd|uri|connection)/i, category: "database" },
  { name: "generic", pattern: /(?:[A-Za-z0-9\-_]{20,})/, category: "generic" },
];

const CONTEXT_KEYWORDS = [
  "password",
  "secret",
  "token",
  "apikey",
  "client_secret",
  "ssh_key",
  "db_password",
  "connection_string",
];

export class SecretDetectionService {
  private classifier = new SecretClassifier();

  detect(text: string, filePath?: string): DetectionResult {
    const findings: SecretFinding[] = [];

    for (const rule of REGEX_RULES) {
      const flags = rule.pattern.flags.includes("g")
        ? rule.pattern.flags
        : `${rule.pattern.flags}g`;
      const regex = new RegExp(rule.pattern.source, flags);
      const matches = text.matchAll(regex);
      for (const match of matches) {
        const candidate = match[0];
        if (!candidate) continue;

        const entropyScore = this.calculateEntropy(candidate);
        const contextScore = this.calculateContextScore(text, match.index ?? 0);
        const category = this.classifier.classify(candidate);
        const confidence = this.classifier.getConfidence(candidate, category);
        const risk = this.calculateRisk(entropyScore, contextScore, confidence);

        findings.push({
          value: candidate,
          category: category as any,
          location: {
            filePath,
            line: this.getLineNumber(text, match.index),
            column: this.getColumnNumber(text, match.index),
          },
          detection: {
            regexMatch: true,
            entropyScore,
            contextScore,
            confidence,
            risk,
            features: this.collectFeatures(candidate, contextScore),
          },
        });
      }
    }

    return {
      findings,
      maxRisk: findings.reduce((max, finding) => Math.max(max, finding.detection.risk), 0),
      summary: this.buildSummary(findings),
    };
  }

  private calculateEntropy(value: string): number {
    const frequency = new Map<string, number>();
    for (const character of value) {
      frequency.set(character, (frequency.get(character) ?? 0) + 1);
    }

    let entropy = 0;
    for (const count of frequency.values()) {
      const probability = count / value.length;
      entropy -= probability * Math.log2(probability);
    }

    return Number((entropy / 8).toFixed(2));
  }

  private calculateContextScore(text: string, index: number): number {
    const windowStart = Math.max(0, index - 120);
    const windowEnd = Math.min(text.length, index + 120);
    const context = text.slice(windowStart, windowEnd).toLowerCase();
    const matches = CONTEXT_KEYWORDS.filter((keyword) => context.includes(keyword));
    return Math.min(1, matches.length / 4);
  }

  private calculateRisk(entropy: number, contextScore: number, confidence: number): number {
    return Number(
      Math.min(1, entropy * 0.3 + contextScore * 0.4 + confidence * 0.3).toFixed(2)
    );
  }

  private collectFeatures(value: string, contextScore: number): string[] {
    const features = ["regex", "entropy"];
    if (contextScore > 0.3) {
      features.push("context-aware");
    }
    if (value.length > 30) {
      features.push("long-secret");
    }
    return features;
  }

  private getLineNumber(text: string, index: number | undefined): number {
    if (index === undefined || index < 0) return 0;
    return text.slice(0, index).split("\n").length;
  }

  private getColumnNumber(text: string, index: number | undefined): number {
    if (index === undefined || index < 0) return 0;
    const lines = text.slice(0, index).split("\n");
    return lines[lines.length - 1].length + 1;
  }

  private buildSummary(findings: SecretFinding[]): string {
    if (findings.length === 0) {
      return "No secrets detected.";
    }
    const byCategory = findings.reduce<Record<string, number>>((acc, item) => {
      acc[item.category] = (acc[item.category] ?? 0) + 1;
      return acc;
    }, {});
    return Object.entries(byCategory)
      .map(([category, count]) => `${count} ${category}`)
      .join(", ");
  }
}
