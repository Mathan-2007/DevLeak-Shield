"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.SecretDetectionService = void 0;
const SecretClassifier_1 = require("./SecretClassifier");
const CryptoService_1 = require("../crypto/CryptoService");
const REGEX_RULES = [
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
class SecretDetectionService {
    constructor(customRules = []) {
        this.classifier = new SecretClassifier_1.SecretClassifier();
        // Patterns that capture assignment-style secrets and config object property values.
        this.SECRET_PATTERNS = [
            // Matches variable names that include password/pass or secret (handles underscores like APP_SECRET)
            { name: "password_assign", pattern: /((?:\b|_)(?:[A-Za-z0-9_]*?(?:password|passwd|pwd|pass|secret)[A-Za-z0-9_]*)(?:\b|_))\s*[:=]\s*["']?([^"'\s;,\)\}]+)["']?/gi, category: "password" },
            // Matches variable names that include key/token/api_key variants
            { name: "key_assign", pattern: /((?:\b|_)(?:[A-Za-z0-9_]*?(?:key|token|api_key|apikey|client_secret|access_key|secret_key|access_token|refresh_token|id_token|session|auth_token|webhook|private_key|privateKey|database_url|connection_string|credentials)[A-Za-z0-9_]*)(?:\b|_))\s*[:=]\s*["']?([^"'\s;,\)\}]+)["']?/gi, category: "api_key" },
            // Matches object literal property assignments such as { apiKey: "...", password: '...' }
            { name: "object_property", pattern: /(?:["'`]?)([A-Za-z0-9_$]*?(?:api[_-]?key|apikey|token|secret|password|passwd|pwd|client_secret|access_key|secret_key|refresh_token|id_token|auth_token|session|webhook|private_key|privateKey|database_url|connection_string|credentials)[A-Za-z0-9_$]*)(?:["'`]?)[ \t]*:[ \t]*["'`]([^"'`]+?)["'`]/gi, category: "api_key" },
        ];
        this.customRules = customRules.map((rule) => ({
            name: rule.name,
            pattern: new RegExp(rule.pattern, "g"),
            category: rule.category ?? "custom",
        }));
    }
    detect(text, filePath) {
        const findings = [];
        const seenCandidates = new Set();
        // Check generic regex rules first
        for (const rule of REGEX_RULES) {
            const flags = rule.pattern.flags.includes("g") ? rule.pattern.flags : `${rule.pattern.flags}g`;
            const regex = new RegExp(rule.pattern.source, flags);
            for (const match of text.matchAll(regex)) {
                const candidate = match[0];
                if (!candidate)
                    continue;
                const candidateKey = `${match.index ?? -1}:${candidate}`;
                if (seenCandidates.has(candidateKey))
                    continue;
                seenCandidates.add(candidateKey);
                const startIndex = match.index ?? 0;
                const entropyScore = this.calculateEntropy(candidate);
                const contextScore = this.calculateContextScore(text, startIndex);
                const contextText = text.slice(Math.max(0, startIndex - 120), Math.min(text.length, startIndex + 120));
                const category = this.classifier.classify(candidate, contextText);
                const confidence = this.classifier.getConfidence(candidate, category);
                const risk = this.calculateRisk(entropyScore, contextScore, confidence);
                findings.push({
                    value: candidate,
                    category: category,
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
        for (const rule of this.customRules) {
            const flags = rule.pattern.flags.includes("g") ? rule.pattern.flags : `${rule.pattern.flags}g`;
            const regex = new RegExp(rule.pattern.source, flags);
            for (const match of text.matchAll(regex)) {
                const candidate = match[0];
                if (!candidate)
                    continue;
                const candidateKey = `${match.index ?? -1}:${candidate}`;
                if (seenCandidates.has(candidateKey))
                    continue;
                seenCandidates.add(candidateKey);
                const startIndex = match.index ?? 0;
                const entropyScore = this.calculateEntropy(candidate);
                const contextScore = this.calculateContextScore(text, startIndex);
                const contextText = text.slice(Math.max(0, startIndex - 120), Math.min(text.length, startIndex + 120));
                const category = rule.category;
                const confidence = this.classifier.getConfidence(candidate, category);
                const risk = this.calculateRisk(entropyScore, contextScore, confidence);
                findings.push({
                    value: candidate,
                    category: category,
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
        // Also check more specific secret value patterns, including assignment and config object properties (value is in capture group 2)
        for (const rule of this.SECRET_PATTERNS) {
            const flags = rule.pattern.flags.includes("g") ? rule.pattern.flags : `${rule.pattern.flags}g`;
            const regex = new RegExp(rule.pattern.source, flags);
            for (const match of text.matchAll(regex)) {
                const full = match[0];
                const value = match[2];
                if (!value)
                    continue;
                const start = (match.index ?? 0) + full.indexOf(value);
                const candidateKey = `${start}:${value}`;
                if (seenCandidates.has(candidateKey))
                    continue;
                seenCandidates.add(candidateKey);
                const entropyScore = this.calculateEntropy(value);
                const contextScore = this.calculateContextScore(text, start);
                const contextText = text.slice(Math.max(0, start - 120), Math.min(text.length, start + 120));
                const category = rule.category;
                const confidence = this.classifier.getConfidence(value, category);
                const risk = this.calculateRisk(entropyScore, contextScore, confidence);
                findings.push({
                    value,
                    category: category,
                    location: {
                        filePath,
                        line: this.getLineNumber(text, start),
                        column: this.getColumnNumber(text, start),
                    },
                    detection: {
                        regexMatch: true,
                        entropyScore,
                        contextScore,
                        confidence,
                        risk,
                        features: this.collectFeatures(value, contextScore),
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
    // Redact detected secrets in the provided text and return the redacted text
    redactSecrets(text) {
        const replacements = [];
        // Helper to schedule a replacement
        const schedule = (start, end, original) => {
            const key = CryptoService_1.CryptoService.generateKey();
            const cipher = CryptoService_1.CryptoService.encrypt(original, key);
            const token = `HIDDEN_SECRET_DO_NOT_DECODE_${cipher}`;
            replacements.push({ start, end, original, replacement: token, line: this.getLineNumber(text, start), column: this.getColumnNumber(text, start) });
        };
        const seen = new Set();
        // Precompute ranges that are already redacted so we don't modify them
        const redactedRanges = [];
        const prefix = "HIDDEN_SECRET_DO_NOT_DECODE_";
        let searchIdx = 0;
        while (true) {
            const idx = text.indexOf(prefix, searchIdx);
            if (idx === -1)
                break;
            // find end of token (next whitespace or line break)
            let j = idx;
            while (j < text.length && !/\s/.test(text[j]))
                j++;
            redactedRanges.push({ start: idx, end: j });
            searchIdx = j;
        }
        const overlapsRedacted = (s, e) => redactedRanges.some((r) => !(e <= r.start || s >= r.end));
        for (const rule of this.customRules) {
            const flags = rule.pattern.flags.includes("g") ? rule.pattern.flags : `${rule.pattern.flags}g`;
            const regex = new RegExp(rule.pattern.source, flags);
            for (const match of text.matchAll(regex)) {
                const candidate = match[0];
                if (!candidate)
                    continue;
                const start = match.index ?? 0;
                const end = start + candidate.length;
                const id = `${start}:${candidate}`;
                if (overlapsRedacted(start, end))
                    continue;
                if (seen.has(id))
                    continue;
                seen.add(id);
                schedule(start, end, candidate);
            }
        }
        // First, capture assignment-style and property-style secrets (value is in capture group 2)
        for (const rule of this.SECRET_PATTERNS) {
            const flags = rule.pattern.flags.includes("g") ? rule.pattern.flags : `${rule.pattern.flags}g`;
            const regex = new RegExp(rule.pattern.source, flags);
            for (const match of text.matchAll(regex)) {
                const full = match[0];
                const value = match[2];
                if (!value)
                    continue;
                const start = (match.index ?? 0) + full.indexOf(value);
                const end = start + value.length;
                const id = `${start}:${value}`;
                if (overlapsRedacted(start, end))
                    continue;
                if (seen.has(id))
                    continue;
                seen.add(id);
                schedule(start, end, value);
            }
        }
        // Then, capture generic regex rule matches
        for (const rule of REGEX_RULES) {
            const flags = rule.pattern.flags.includes("g") ? rule.pattern.flags : `${rule.pattern.flags}g`;
            const regex = new RegExp(rule.pattern.source, flags);
            for (const match of text.matchAll(regex)) {
                const candidate = match[0];
                if (!candidate)
                    continue;
                const start = match.index ?? 0;
                const end = start + candidate.length;
                const id = `${start}:${candidate}`;
                if (overlapsRedacted(start, end))
                    continue;
                if (seen.has(id))
                    continue;
                seen.add(id);
                schedule(start, end, candidate);
            }
        }
        // Apply replacements from end -> start to avoid shifting indexes
        replacements.sort((a, b) => b.start - a.start);
        let redacted = text;
        for (const r of replacements) {
            redacted = redacted.slice(0, r.start) + r.replacement + redacted.slice(r.end);
        }
        return {
            redactedText: redacted,
            replacements: replacements.map((r) => ({ original: r.original, replacement: r.replacement, line: r.line, column: r.column })),
        };
    }
    calculateEntropy(value) {
        const frequency = new Map();
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
    calculateContextScore(text, index) {
        const windowStart = Math.max(0, index - 120);
        const windowEnd = Math.min(text.length, index + 120);
        const context = text.slice(windowStart, windowEnd).toLowerCase();
        const matches = CONTEXT_KEYWORDS.filter((keyword) => context.includes(keyword));
        return Math.min(1, matches.length / 4);
    }
    calculateRisk(entropy, contextScore, confidence) {
        return Number(Math.min(1, entropy * 0.3 + contextScore * 0.4 + confidence * 0.3).toFixed(2));
    }
    collectFeatures(value, contextScore) {
        const features = ["regex", "entropy"];
        if (contextScore > 0.3) {
            features.push("context-aware");
        }
        if (value.length > 30) {
            features.push("long-secret");
        }
        return features;
    }
    getLineNumber(text, index) {
        if (index === undefined || index < 0)
            return 0;
        return text.slice(0, index).split("\n").length;
    }
    getColumnNumber(text, index) {
        if (index === undefined || index < 0)
            return 0;
        const lines = text.slice(0, index).split("\n");
        return lines[lines.length - 1].length + 1;
    }
    buildSummary(findings) {
        if (findings.length === 0) {
            return "No secrets detected.";
        }
        const byCategory = findings.reduce((acc, item) => {
            acc[item.category] = (acc[item.category] ?? 0) + 1;
            return acc;
        }, {});
        return Object.entries(byCategory)
            .map(([category, count]) => `${count} ${category}`)
            .join(", ");
    }
}
exports.SecretDetectionService = SecretDetectionService;
//# sourceMappingURL=SecretDetectionService.js.map