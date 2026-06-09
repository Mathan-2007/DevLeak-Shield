import { SecretCategory } from "../../types";

const CATEGORY_PATTERNS: Record<SecretCategory, RegExp> = {
  openai: /sk-[A-Za-z0-9]{10,}/,
  aws: /AKIA[0-9A-Z]{16}|A3T[A-Z0-9]{16}|ACCA[0-9A-Z]{16}/,
  github: /ghp_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{20,}/,
  jwt: /^[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+$/,
  ssh: /-----BEGIN (RSA|OPENSSH|DSA|EC) PRIVATE KEY-----/,
  database: /(postgres|mongodb|mysql|sqlserver).*(password|pwd|uri|connection)/i,
  api_key: /api[_-]?key|apikey|client_secret/i,
  generic: /.*/,
};

export class SecretClassifier {
  classify(candidate: string): SecretCategory {
    for (const category of Object.keys(CATEGORY_PATTERNS) as SecretCategory[]) {
      if (CATEGORY_PATTERNS[category].test(candidate)) {
        return category;
      }
    }

    return "generic";
  }

  getConfidence(candidate: string, category: SecretCategory): number {
    const pattern = CATEGORY_PATTERNS[category];
    if (!pattern.test(candidate)) {
      return 0.2;
    }

    return Math.min(1, 0.5 + candidate.length / 64);
  }
}
