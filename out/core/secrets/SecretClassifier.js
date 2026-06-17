"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.SecretClassifier = void 0;
const CATEGORY_PATTERNS = {
  CLOUD_KEYS: [
    /AKIA[0-9A-Z]{16}/,                          // AWS
    /ASIA[0-9A-Z]{16}/,                          // AWS Temp
    /AIza[0-9A-Za-z\-_]{35}/,                    // Google
    /ya29\.[0-9A-Za-z\-_]+/,                     // Google OAuth
    /xox[baprs]-[A-Za-z0-9-]+/,                  // Slack
  ],

  GITHUB: [
    /ghp_[A-Za-z0-9]{36}/,
    /github_pat_[A-Za-z0-9_]{20,}/,
    /gho_[A-Za-z0-9]{36}/,
    /ghu_[A-Za-z0-9]{36}/,
  ],

  OPENAI: [
    /sk-[A-Za-z0-9]{20,}/,
    /sk-proj-[A-Za-z0-9_-]{20,}/,
  ],

  STRIPE: [
    /pk_live_[A-Za-z0-9]+/,
    /sk_live_[A-Za-z0-9]+/,
  ],

  DISCORD: [
    /[MN][A-Za-z\d]{23}\.[\w-]{6}\.[\w-]{27}/,
  ],

  JWT: [
    /^[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+$/,
  ],

  PRIVATE_KEYS: [
    /-----BEGIN RSA PRIVATE KEY-----/,
    /-----BEGIN OPENSSH PRIVATE KEY-----/,
    /-----BEGIN EC PRIVATE KEY-----/,
    /-----BEGIN PRIVATE KEY-----/,
    /-----BEGIN PGP PRIVATE KEY BLOCK-----/,
  ],

  DATABASE_URLS: [
    /mongodb(\+srv)?:\/\/.+/,
    /postgres(ql)?:\/\/.+/,
    /mysql:\/\/.+/,
    /redis:\/\/.+/,
  ],

  PASSWORDS: [
    /(password|passwd|pwd)\s*[:=]\s*["'][^"']+["']/i,
  ],

  API_KEYS: [
    /api[_-]?key/i,
    /client[_-]?secret/i,
    /access[_-]?token/i,
    /refresh[_-]?token/i,
    /bearer\s+[a-z0-9\-_\.]+/i,
  ],

  WEBHOOKS: [
    /https:\/\/hooks\.slack\.com\/services\/.*/,
    /https:\/\/discord\.com\/api\/webhooks\/.*/,
  ],

  CRYPTO: [
    /0x[a-fA-F0-9]{64}/,
    /-----BEGIN BITCOIN PRIVATE KEY-----/,
  ],
};
class SecretClassifier {
    classify(candidate) {
        for (const category of Object.keys(CATEGORY_PATTERNS)) {
            const patterns = CATEGORY_PATTERNS[category];
            for (const pattern of patterns) {
                if (pattern.test(candidate)) {
                    return category;
                }
            }
        }
        return "generic";
    }
    getConfidence(candidate, category) {
        const patterns = CATEGORY_PATTERNS[category] || [];
        const isMatch = patterns.some(p => p.test(candidate));
        if (!isMatch) {
            return 0.2; // Generic confidence for non-matching category
        }
        return Math.min(1, 0.5 + candidate.length / 64);
    }
}
exports.SecretClassifier = SecretClassifier;
//# sourceMappingURL=SecretClassifier.js.map