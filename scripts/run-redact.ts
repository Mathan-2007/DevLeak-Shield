import * as fs from 'fs';
import * as path from 'path';
import { SecretDetectionService } from '../src/core/secrets/SecretDetectionService';

const svc = new SecretDetectionService();
const inPath = path.join(__dirname, '..', 'samples', 'customer-provided.env');
const outPath = path.join(__dirname, '..', 'samples', 'customer-provided.redacted.env');

const text = fs.readFileSync(inPath, 'utf8');
const result = svc.redactSecrets(text);
fs.writeFileSync(outPath, result.redactedText, 'utf8');
console.log('Wrote redacted output to', outPath);
console.log('Replacements:', result.replacements);
