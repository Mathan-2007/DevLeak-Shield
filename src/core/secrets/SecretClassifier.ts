import { SecretCategory } from "../../types";

const CATEGORY_PATTERNS: Record<SecretCategory, RegExp> = {
  openai: /sk-[A-Za-z0-9_-]{20,}/,
  anthropic: /sk-ant-[A-Za-z0-9_-]{20,}/,
  aws: /AKIA[0-9A-Z]{16}|A3T[A-Z0-9]{16}|ACCA[0-9A-Z]{16}/,
  github: /ghp_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{20,}/,
  jwt: /\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b/,
  ssh: /-----BEGIN (RSA|OPENSSH|DSA|EC) PRIVATE KEY-----/,
  database: /(postgres|mongodb|mysql|sqlserver|oracle).*(password|pwd|uri|connection)/i,
  api_key: /api[_-]?key|apikey|client_secret/i,
  generic: /.*/,
  private_key: /-----BEGIN (RSA|DSA|EC|OPENSSH|PGP|PRIVATE) KEY/,
  stripe: /sk_(live|test)_[A-Za-z0-9]{20,}/,
  slack: /xox[baprs]-[A-Za-z0-9-]{10,}/,
  discord: /[MN][A-Za-z\d]{23}\.[\w-]{6}\.[\w-]{27}/,
  firebase: /https:\/\/[A-Za-z0-9-]+\.firebaseio\.com/,
  kubernetes: /apiVersion:\s*v1[\s\S]*clusters:/,
  docker: /"auth"\s*:\s*"[A-Za-z0-9+/=]+"/i,
  azure: /[A-Za-z0-9+/]{86}==/,
  npm: /npm_[A-Za-z0-9]{36}/,
  gitlab: /glpat-[A-Za-z0-9_-]{20,}/,
  shopify: /shpat_[a-f0-9]{32}/i,
  heroku: /heroku[a-z0-9]{32}/i,
  sendgrid: /SG\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}/,
  mailgun: /key-[a-z0-9]{32}/,
  telegram: /\d{8,10}:[A-Za-z0-9_-]{35}/,
  twilio: /AC[a-f0-9]{32}|SK[a-f0-9]{32}/i,
  google: /AIza[0-9A-Za-z\-_]{35}|[0-9]+-[a-z0-9]+\.apps\.googleusercontent\.com/,
  password: /\b(password|passwd|pwd|secret)\b/i,
  bearer: /Bearer\s+[A-Za-z0-9\-._~+/]+=*/i,
  access_token: /\b(access[_-]?token|refresh[_-]?token|id[_-]?token)\b/i,
  cookie: /\b(sessionid|connect\.sid|auth_token|csrf_token)\b/i,
  custom: /$^/,
};

export class SecretClassifier {
  classify(candidate: string, surroundingContext?: string): SecretCategory {
    // Prefer explicit pattern matches first
    for (const category of Object.keys(CATEGORY_PATTERNS) as SecretCategory[]) {
      if (category === "custom") continue;
      if (CATEGORY_PATTERNS[category].test(candidate)) {
        return category;
      }
    }

    // Heuristics: if candidate starts with known prefixes, use that
    if (candidate.startsWith("sk-ant-")) return "anthropic";
    if (candidate.startsWith("sk-")) {
      // if surrounding context mentions "key" or "api", prefer openai
      const ctx = (surroundingContext || "").toLowerCase();
      if (ctx.includes("key") || ctx.includes("api") || ctx.includes("token")) return "openai";
      return "api_key";
    }

    return "generic";
  }

  getConfidence(candidate: string, category: SecretCategory): number {
    if (category === "custom") {
      return 0.2;
    }

    const pattern = CATEGORY_PATTERNS[category];
    if (pattern && !pattern.test(candidate)) {
      return 0.2;
    }

    return Math.min(1, 0.5 + candidate.length / 64);
  }
}