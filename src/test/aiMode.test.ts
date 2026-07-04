/**
 * aiMode.test.ts
 *
 * ASSUMPTIONS:
 * - AI Mode maintains an in-memory backup map: { documentUri: originalText }
 * - Functions: maskOpenEditorSecrets(documentText, detector): { masked, backup }
 *              restoreOpenEditorSecrets(documentUri, backupStore): originalText | null
 * - Per your own docs: there is NO threshold gating here — any detection
 *   triggers masking. Tests below intentionally confirm that documented
 *   behavior rather than assuming a threshold exists.
 */

import { expect } from "chai";
import { SecretDetectionService } from "./SecretDetectionService";
import { maskOpenEditorSecrets, restoreOpenEditorSecrets } from "./aiMode";

describe("AI Mode: mask open editor content", () => {
  let detector: SecretDetectionService;

  beforeEach(() => {
    detector = new SecretDetectionService();
  });

  it("masks a low-confidence-looking secret too, since no threshold gating exists", () => {
    // Deliberately a borderline case: short, low-entropy "password-like" string
    const text = "password = 'abc123'";
    const { masked } = maskOpenEditorSecrets(text, detector);
    expect(masked).to.not.include("abc123");
  });

  it("masks all secret categories present in a mixed document", () => {
    const text = [
      "OPENAI_API_KEY=sk-live-a8f9d7e6b5c4d3e2f1a0",
      "const token = 'ghp_1234567890abcdef1234567890abcdef1234';",
      "mongodb+srv://user:pass@cluster0.mongodb.net/db",
    ].join("\n");

    const { masked } = maskOpenEditorSecrets(text, detector);
    expect(masked).to.not.include("sk-live-a8f9d7e6b5c4d3e2f1a0");
    expect(masked).to.not.include("ghp_1234567890abcdef1234567890abcdef1234");
    expect(masked).to.not.include("mongodb+srv://user:pass@cluster0.mongodb.net/db");
  });

  it("stores an in-memory backup that exactly reconstructs the original", () => {
    const original = "OPENAI_API_KEY=sk-live-a8f9d7e6b5c4d3e2f1a0";
    const backupStore: Record<string, string> = {};
    const uri = "file:///test/config.env";

    const { masked, backup } = maskOpenEditorSecrets(original, detector);
    backupStore[uri] = backup;

    const restored = restoreOpenEditorSecrets(uri, backupStore);
    expect(restored).to.equal(original);
    expect(masked).to.not.equal(original);
  });

  it("returns null (not a thrown error) when restoring a document with no backup", () => {
    const restored = restoreOpenEditorSecrets("file:///never-masked.ts", {});
    expect(restored).to.equal(null);
  });

  it("leaves code with no secrets completely unchanged", () => {
    const text = "export function sum(a: number, b: number) { return a + b; }";
    const { masked } = maskOpenEditorSecrets(text, detector);
    expect(masked).to.equal(text);
  });

  it("does not crash on very large documents (basic perf/robustness check)", () => {
    const bigText = ("const x = 1;\n").repeat(20000) + "OPENAI_API_KEY=sk-live-a8f9d7e6b5c4d3e2f1a0";
    expect(() => maskOpenEditorSecrets(bigText, detector)).to.not.throw();
  });
});
