import { SecretClassifier } from "./SecretClassifier";
import { SecretFinding, DetectionResult } from "../../types";

const REGEX_RULES: Array<{ name: string; pattern: RegExp; category: string }> = [
  // AI & LLM API Keys
  { name: "openai", pattern: /sk-[A-Za-z0-9_-]{20,}/, category: "openai" },
  { name: "anthropic", pattern: /sk-ant-[A-Za-z0-9_-]{20,}/, category: "anthropic" },
  
  // GitHub Tokens
  { name: "github_pat", pattern: /github_pat_[A-Za-z0-9_]{20,}/, category: "github" },
  { name: "github_classic", pattern: /ghp_[A-Za-z0-9]{36}/, category: "github" },
  { name: "github_oauth", pattern: /gho_[A-Za-z0-9]{36}/, category: "github" },
  { name: "github_app", pattern: /ghu_[A-Za-z0-9]{36}/, category: "github" },
  { name: "github_refresh", pattern: /ghr_[A-Za-z0-9]{36}/, category: "github" },
  { name: "github_server", pattern: /ghs_[A-Za-z0-9]{36}/, category: "github" },
  
  // AWS Keys
  { name: "aws_access_key", pattern: /(AKIA|ASIA|AGPA|AIDA|AROA|AIPA)[A-Z0-9]{16}/, category: "aws" },
  { name: "aws_secret", pattern: /aws(.{0,20})?(secret|access).{0,20}[=:]["']?[A-Za-z0-9\/+=]{40}/i, category: "aws" },
  
  // Google APIs
  { name: "google_api_key", pattern: /AIza[0-9A-Za-z\-_]{35}/, category: "google" },
  { name: "google_oauth", pattern: /[0-9]+-[a-z0-9]+\.apps\.googleusercontent\.com/, category: "google" },
  
  // Stripe
  { name: "stripe_secret", pattern: /sk_(live|test)_[A-Za-z0-9]{20,}/, category: "stripe" },
  { name: "stripe_publishable", pattern: /pk_(live|test)_[A-Za-z0-9]{20,}/, category: "stripe" },
  
  // Slack
  { name: "slack_token", pattern: /xox[baprs]-[A-Za-z0-9-]{10,}/, category: "slack" },
  { name: "slack_webhook", pattern: /https:\/\/hooks\.slack\.com\/services\/[A-Za-z0-9/_-]+/, category: "slack" },
  
  // Discord
  { name: "discord_token", pattern: /[MN][A-Za-z\d]{23}\.[\w-]{6}\.[\w-]{27}/, category: "discord" },
  { name: "discord_webhook", pattern: /https:\/\/discord(?:app)?\.com\/api\/webhooks\/\d+\/[\w-]+/, category: "discord" },
  
  // Communication Platforms
  { name: "telegram_bot", pattern: /\d{8,10}:[A-Za-z0-9_-]{35}/, category: "telegram" },
  { name: "twilio_sid", pattern: /AC[a-f0-9]{32}/i, category: "twilio" },
  { name: "twilio_auth", pattern: /SK[a-f0-9]{32}/i, category: "twilio" },
  
  // Email & Messaging
  { name: "sendgrid", pattern: /SG\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}/, category: "sendgrid" },
  { name: "mailgun", pattern: /key-[a-z0-9]{32}/, category: "mailgun" },
  
  // Firebase
  { name: "firebase_url", pattern: /https:\/\/[A-Za-z0-9-]+\.firebaseio\.com/, category: "firebase" },
  
  // Tokens & Authentication
  { name: "jwt", pattern: /\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b/, category: "jwt" },
  { name: "bearer", pattern: /Bearer\s+[A-Za-z0-9\-._~+/]+=*/i, category: "bearer" },
  { name: "api_key", pattern: /\b(api[_-]?key|apikey|client[_-]?secret|secret[_-]?key)\b/i, category: "api_key" },
  { name: "access_token", pattern: /\b(access[_-]?token|refresh[_-]?token|id[_-]?token)\b/i, category: "access_token" },
  { name: "cookie", pattern: /\b(sessionid|connect\.sid|auth_token|csrf_token)\b/i, category: "cookie" },
  
  // Database Connection Strings
  { name: "mongodb", pattern: /mongodb(\+srv)?:\/\/[^"'\s]+/i, category: "database" },
  { name: "postgres", pattern: /postgres(ql)?:\/\/[^"'\s]+/i, category: "database" },
  { name: "mysql", pattern: /mysql:\/\/[^"'\s]+/i, category: "database" },
  { name: "redis", pattern: /redis:\/\/[^"'\s]+/i, category: "database" },
  { name: "database_uri", pattern: /(postgres|mongodb|mysql|mssql|oracle|redis):\/\/[^"'\s]+/i, category: "database" },
  
  // Private Keys & Certificates
  { name: "ssh_private", pattern: /-----BEGIN OPENSSH PRIVATE KEY-----/, category: "private_key" },
  { name: "rsa_private", pattern: /-----BEGIN RSA PRIVATE KEY-----/, category: "private_key" },
  { name: "dsa_private", pattern: /-----BEGIN DSA PRIVATE KEY-----/, category: "private_key" },
  { name: "ec_private", pattern: /-----BEGIN EC PRIVATE KEY-----/, category: "private_key" },
  { name: "pgp_private", pattern: /-----BEGIN PGP PRIVATE KEY BLOCK-----/, category: "private_key" },
  { name: "pem_private", pattern: /-----BEGIN PRIVATE KEY-----/, category: "private_key" },
  
  // Infrastructure & Container Config
  { name: "kubeconfig", pattern: /apiVersion:\s*v1[\s\S]*clusters:/, category: "kubernetes" },
  { name: "docker_auth", pattern: /"auth"\s*:\s*"[A-Za-z0-9+/=]+"/i, category: "docker" },
  
  // Azure & Cloud
  { name: "azure_key", pattern: /[A-Za-z0-9+/]{86}==/, category: "azure" },
  
  // Package Managers
  { name: "npm_token", pattern: /npm_[A-Za-z0-9]{36}/, category: "npm" },
  { name: "gitlab", pattern: /glpat-[A-Za-z0-9_-]{20,}/, category: "gitlab" },
  
  // Platform-specific tokens
  { name: "shopify", pattern: /shpat_[a-f0-9]{32}/i, category: "shopify" },
  { name: "heroku", pattern: /heroku[a-z0-9]{32}/i, category: "heroku" },
  
  // Generic patterns (low priority)
  { name: "password", pattern: /\b(password|passwd|pwd|secret)\b/i, category: "password" },
];

const CONTEXT_KEYWORDS = [
  "password",
  "secret",
  "token",
  "apikey",
  "api_key",
  "client_secret",
  "ssh_key",
  "db_password",
  "connection_string",
  "private_key",
  "access_key",
  "secret_key",
  "refresh_token",
  "id_token",
  "bearer",
  "authorization",
  "credentials",
  "auth",
  "webhook",
  "signing_key",
  "encryption_key",
  "decrypt",
  "cipher",
  "certificate",
  "certificate_key",
  "api_secret",
  "access_token",
  "session",
  "firebase",
  "database_url",
  "db_url",
  "mongodb_uri",
  "postgres_uri",
  "mysql_uri",
];

export class SecretDetectionService {
  private classifier = new SecretClassifier();

  detect(text: string, filePath?: string): DetectionResult {
    const findings: SecretFinding[] = [];
    const seenCandidates = new Set<string>();

    for (const rule of REGEX_RULES) {
      const flags = rule.pattern.flags.includes("g")
        ? rule.pattern.flags
        : `${rule.pattern.flags}g`;
      const regex = new RegExp(rule.pattern.source, flags);
      const matches = text.matchAll(regex);
      for (const match of matches) {
        const candidate = match[0];
        if (!candidate) continue;
        const candidateKey = `${match.index ?? -1}:${candidate}`;
        if (seenCandidates.has(candidateKey)) continue;
        seenCandidates.add(candidateKey);

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
