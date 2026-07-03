"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const fs = require("fs");
const path = require("path");
const SecretDetectionService_1 = require("../src/core/secrets/SecretDetectionService");
const svc = new SecretDetectionService_1.SecretDetectionService();
const inPath = path.join(__dirname, '..', 'samples', 'customer-provided.env');
const outPath = path.join(__dirname, '..', 'samples', 'customer-provided.redacted.env');
const text = fs.readFileSync(inPath, 'utf8');
const result = svc.redactSecrets(text);
fs.writeFileSync(outPath, result.redactedText, 'utf8');
console.log('Wrote redacted output to', outPath);
console.log('Replacements:', result.replacements);
//# sourceMappingURL=run-redact.js.map