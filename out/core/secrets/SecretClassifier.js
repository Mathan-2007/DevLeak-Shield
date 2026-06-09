"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.SecretClassifier = void 0;
const CATEGORY_PATTERNS = {
    openai: /sk-[A-Za-z0-9]{10,}/,
    aws: /AKIA[0-9A-Z]{16}|A3T[A-Z0-9]{16}|ACCA[0-9A-Z]{16}/,
    github: /ghp_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{20,}/,
    jwt: /^[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+$/,
    ssh: /-----BEGIN (RSA|OPENSSH|DSA|EC) PRIVATE KEY-----/,
    database: /(postgres|mongodb|mysql|sqlserver).*(password|pwd|uri|connection)/i,
    api_key: /api[_-]?key|apikey|client_secret/i,
    generic: /.*/,
};
class SecretClassifier {
    classify(candidate) {
        for (const category of Object.keys(CATEGORY_PATTERNS)) {
            if (CATEGORY_PATTERNS[category].test(candidate)) {
                return category;
            }
        }
        return "generic";
    }
    getConfidence(candidate, category) {
        const pattern = CATEGORY_PATTERNS[category];
        if (!pattern.test(candidate)) {
            return 0.2;
        }
        return Math.min(1, 0.5 + candidate.length / 64);
    }
}
exports.SecretClassifier = SecretClassifier;
//# sourceMappingURL=SecretClassifier.js.map