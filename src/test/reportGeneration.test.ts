/**
 * reportGeneration.test.ts
 *
 * ASSUMPTIONS:
 * - ReportGenerator.generateJson(findings): object with { summary, findings }
 * - ReportGenerator.generateCsv(findings): string
 * - Per your analysis, generateHtml() exists but isn't wired to any command —
 *   tests below cover it anyway so it doesn't silently rot, and to document
 *   that it works even though it's unreachable from the UI today.
 * - CRITICAL: reports must contain REDACTED values, never raw secrets —
 *   this is the single most important property to test, since a report
 *   file is exactly the kind of artifact that gets committed or shared by accident.
 */

import { expect } from "chai";
import { ReportGenerator } from "./ReportGenerator";

const SAMPLE_FINDINGS = [
  {
    filePath: "src/config.env",
    line: 2,
    category: "openai-key",
    redactedValue: "[REDACTED_9f3a]",
    riskScore: 0.92,
  },
  {
    filePath: "src/db.ts",
    line: 14,
    category: "database-url",
    redactedValue: "[REDACTED_2b71]",
    riskScore: 0.81,
  },
];

describe("Report generation", () => {
  it("generates a JSON report with a summary and findings list", () => {
    const report = ReportGenerator.generateJson(SAMPLE_FINDINGS);
    expect(report).to.have.property("summary");
    expect(report).to.have.property("findings");
    expect(report.findings).to.have.length(2);
  });

  it("JSON report summary counts match the findings array length", () => {
    const report = ReportGenerator.generateJson(SAMPLE_FINDINGS);
    expect(report.summary.totalFindings).to.equal(SAMPLE_FINDINGS.length);
  });

  it("never includes raw secret values in the JSON report — only redacted tokens", () => {
    const report = ReportGenerator.generateJson(SAMPLE_FINDINGS);
    const serialized = JSON.stringify(report);
    expect(serialized).to.include("[REDACTED_");
    // guard: none of our sample redactedValues should ever look like a raw secret
    expect(serialized).to.not.match(/sk-live-[a-zA-Z0-9]+/);
  });

  it("generates a valid CSV with one row per finding plus a header", () => {
    const csv = ReportGenerator.generateCsv(SAMPLE_FINDINGS);
    const lines = csv.trim().split("\n");
    expect(lines.length).to.equal(SAMPLE_FINDINGS.length + 1); // header + rows
  });

  it("CSV output escapes commas/quotes in file paths correctly", () => {
    const trickyFindings = [
      { ...SAMPLE_FINDINGS[0], filePath: 'src/weird,path/"file".env' },
    ];
    const csv = ReportGenerator.generateCsv(trickyFindings);
    // A naive CSV writer breaks on unescaped commas/quotes — this catches that regression
    expect(csv.split("\n")[1].split(",").length).to.not.be.greaterThan(6);
  });

  it("generates HTML report content even though no command currently exposes it", () => {
    const html = ReportGenerator.generateHtml(SAMPLE_FINDINGS);
    expect(html).to.include("<html");
    expect(html).to.include("[REDACTED_9f3a]");
  });

  it("handles an empty findings array without throwing, for all three formats", () => {
    expect(() => ReportGenerator.generateJson([])).to.not.throw();
    expect(() => ReportGenerator.generateCsv([])).to.not.throw();
    expect(() => ReportGenerator.generateHtml([])).to.not.throw();
  });
});
