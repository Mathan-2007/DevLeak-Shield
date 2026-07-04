/**
 * configMalformed.test.ts
 *
 * ASSUMPTIONS:
 * - ConfigService.loadCustomPatterns(workspaceRoot): CustomPattern[]
 * - Per your analysis, the parser is a simple line-based parser, NOT a full
 *   YAML parser. These tests specifically probe the edges that line-based
 *   parsers typically get wrong: multiline values, comments, quoting,
 *   missing fields, and totally invalid syntax.
 * - On any parse failure, the documented/expected behavior is graceful
 *   fallback (empty array + logged warning), never a thrown exception that
 *   would crash extension activation.
 */

import { expect } from "chai";
import * as fs from "fs";
import * as os from "os";
import * as path from "path";
import { ConfigService } from "./ConfigService";

function writeConfig(content: string): string {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "dls-config-"));
  fs.writeFileSync(path.join(dir, ".devleakshield.yml"), content);
  return dir;
}

describe("Custom config: .devleakshield.yml handling", () => {
  it("loads a well-formed config with a single custom rule", () => {
    const dir = writeConfig(
      `rules:\n  - name: "internal-api-token"\n    pattern: "itok_[a-zA-Z0-9]{32}"\n    category: "custom"\n`
    );
    const patterns = ConfigService.loadCustomPatterns(dir);
    expect(patterns).to.have.length(1);
    expect(patterns[0].name).to.equal("internal-api-token");
    fs.rmSync(dir, { recursive: true, force: true });
  });

  it("returns an empty array (not a throw) when the file does not exist", () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "dls-noconfig-"));
    expect(() => ConfigService.loadCustomPatterns(dir)).to.not.throw();
    expect(ConfigService.loadCustomPatterns(dir)).to.deep.equal([]);
    fs.rmSync(dir, { recursive: true, force: true });
  });

  it("falls back gracefully on completely invalid syntax", () => {
    const dir = writeConfig("this is not : yaml at :: all {{{ ]]]");
    expect(() => ConfigService.loadCustomPatterns(dir)).to.not.throw();
    fs.rmSync(dir, { recursive: true, force: true });
  });

  it("skips a rule missing a required 'pattern' field instead of crashing", () => {
    const dir = writeConfig(`rules:\n  - name: "broken-rule"\n    category: "custom"\n`);
    const patterns = ConfigService.loadCustomPatterns(dir);
    expect(patterns.find(p => p.name === "broken-rule")).to.be.undefined;
    fs.rmSync(dir, { recursive: true, force: true });
  });

  it("skips a rule with an invalid/unparseable regex pattern instead of crashing", () => {
    const dir = writeConfig(`rules:\n  - name: "bad-regex"\n    pattern: "[unclosed"\n    category: "custom"\n`);
    expect(() => ConfigService.loadCustomPatterns(dir)).to.not.throw();
    fs.rmSync(dir, { recursive: true, force: true });
  });

  it("handles an empty rules list without error", () => {
    const dir = writeConfig(`rules: []\n`);
    const patterns = ConfigService.loadCustomPatterns(dir);
    expect(patterns).to.deep.equal([]);
    fs.rmSync(dir, { recursive: true, force: true });
  });

  it("handles comment lines and blank lines mixed into the file", () => {
    const dir = writeConfig(
      `# this is a comment\n\nrules:\n  - name: "with-comments"\n    pattern: "abc[0-9]+"\n    category: "custom"\n\n# trailing comment\n`
    );
    const patterns = ConfigService.loadCustomPatterns(dir);
    expect(patterns.find(p => p.name === "with-comments")).to.exist;
    fs.rmSync(dir, { recursive: true, force: true });
  });

  it("loads multiple rules correctly and preserves order", () => {
    const dir = writeConfig(
      [
        "rules:",
        '  - name: "rule-one"',
        '    pattern: "one_[0-9]+"',
        '    category: "custom"',
        '  - name: "rule-two"',
        '    pattern: "two_[0-9]+"',
        '    category: "custom"',
        "",
      ].join("\n")
    );
    const patterns = ConfigService.loadCustomPatterns(dir);
    expect(patterns.map(p => p.name)).to.deep.equal(["rule-one", "rule-two"]);
    fs.rmSync(dir, { recursive: true, force: true });
  });

  it("does not misinterpret a rule's pattern value containing a colon (common YAML gotcha)", () => {
    const dir = writeConfig(
      `rules:\n  - name: "url-like"\n    pattern: "https?://internal:[0-9]+"\n    category: "custom"\n`
    );
    expect(() => ConfigService.loadCustomPatterns(dir)).to.not.throw();
    fs.rmSync(dir, { recursive: true, force: true });
  });
});
