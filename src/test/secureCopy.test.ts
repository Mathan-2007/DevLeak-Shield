/**
 * secureCopy.test.ts
 *
 * ASSUMPTIONS (adjust to match your real exports):
 * - CryptoService exports: generateKey(), encrypt(plaintext, key), decrypt(payload, key)
 * - SecretDetectionService exports: scan(text: string): Finding[]
 * - A function `secureCopyTransform(text, detectionService, cryptoService, key)`
 *   exists (or lives inline in extension.ts) that:
 *     1. Scans text for findings
 *     2. Encrypts each finding's value
 *     3. Replaces it with a `[REDACTED_xxxx]`-style token
 *   If this logic is inline inside extension.ts's smartCopy command handler,
 *   extract it into an exported pure function so it's testable in isolation —
 *   that refactor alone is worth doing regardless of these tests.
 */

import { expect } from "chai";
import { CryptoService } from "./CryptoService";
import { SecretDetectionService } from "./SecretDetectionService";
import { secureCopyTransform } from "./secureCopyTransform"; // extract if inline

describe("Secure Copy workflow", () => {
  let crypto: CryptoService;
  let detector: SecretDetectionService;
  let key: string;

  beforeEach(() => {
    crypto = new CryptoService();
    detector = new SecretDetectionService();
    key = crypto.generateKey();
  });

  it("replaces a detected OpenAI key with a redacted token", () => {
    const input = "OPENAI_API_KEY=sk-live-a8f9d7e6b5c4d3e2f1a0";
    const result = secureCopyTransform(input, detector, crypto, key);

    expect(result.output).to.not.include("sk-live-a8f9d7e6b5c4d3e2f1a0");
    expect(result.output).to.match(/\[REDACTED_[a-zA-Z0-9]+\]/);
    expect(result.findingsCount).to.equal(1);
  });

  it("replaces multiple distinct secrets independently with unique tokens", () => {
    const input = [
      "OPENAI_API_KEY=sk-live-a8f9d7e6b5c4d3e2f1a0",
      "DATABASE_PASSWORD=root12345",
      "AWS_SECRET_KEY=wJalrXUtnFEMI/K7MDENG",
    ].join("\n");

    const result = secureCopyTransform(input, detector, crypto, key);
    const tokens = [...result.output.matchAll(/\[REDACTED_([a-zA-Z0-9]+)\]/g)].map(m => m[1]);

    expect(result.findingsCount).to.equal(3);
    expect(new Set(tokens).size).to.equal(3); // tokens must be unique, not reused
  });

  it("leaves plain, non-secret text completely untouched", () => {
    const input = "const greeting = 'hello world';\nfunction add(a, b) { return a + b; }";
    const result = secureCopyTransform(input, detector, crypto, key);

    expect(result.output).to.equal(input);
    expect(result.findingsCount).to.equal(0);
  });

  it("does not leak plaintext secret value anywhere in the transformed output", () => {
    const secret = "sk-live-a8f9d7e6b5c4d3e2f1a0";
    const input = `OPENAI_API_KEY=${secret}`;
    const result = secureCopyTransform(input, detector, crypto, key);

    expect(result.output).to.not.include(secret);
    // also guard against partial leakage (e.g. first/last N chars echoed for "readability")
    expect(result.output).to.not.include(secret.slice(0, 8));
    expect(result.output).to.not.include(secret.slice(-8));
  });

  it("produces a token that this same key can later decrypt back to the original", () => {
    const secret = "sk-live-a8f9d7e6b5c4d3e2f1a0";
    const input = `OPENAI_API_KEY=${secret}`;
    const result = secureCopyTransform(input, detector, crypto, key);

    const tokenMatch = result.output.match(/\[REDACTED_([a-zA-Z0-9]+)\]/);
    expect(tokenMatch, "expected a redacted token in output").to.not.be.null;

    const restored = crypto.decrypt(result.tokenMap![tokenMatch![1]], key);
    expect(restored).to.equal(secret);
  });

  it("does not throw on empty input", () => {
    expect(() => secureCopyTransform("", detector, crypto, key)).to.not.throw();
  });

  it("handles input with no line breaks (single long line) without missing secrets", () => {
    const input = "config: OPENAI_API_KEY=sk-live-a8f9d7e6b5c4d3e2f1a0; DATABASE_PASSWORD=root12345;";
    const result = secureCopyTransform(input, detector, crypto, key);
    expect(result.findingsCount).to.equal(2);
  });
});
