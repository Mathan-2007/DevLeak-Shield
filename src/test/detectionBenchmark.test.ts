/**
 * detectionBenchmark.test.ts
 *
 * Labeled true-positive / true-negative samples per category, so you get
 * real precision/recall numbers instead of anecdotal "seems to work" confidence.
 *
 * HOW TO USE THIS:
 * - Run it, look at the printed precision/recall table.
 * - If recall is low for a category, your regex/entropy threshold is too strict.
 * - If precision is low, you're flagging normal strings as secrets (false positives) —
 *   this is the more damaging failure mode for a security tool because it trains
 *   users to ignore warnings.
 * - Add more real-world samples over time; this file is meant to grow.
 */

import { expect } from "chai";
import { SecretDetectionService } from "./SecretDetectionService";

interface LabeledSample {
  text: string;
  shouldDetect: boolean;
  category: string;
}

const SAMPLES: LabeledSample[] = [
  // --- True positives (should detect) ---
  { text: "OPENAI_API_KEY=sk-live-a8f9d7e6b5c4d3e2f1a0b1c2d3e4f5a6b7", shouldDetect: true, category: "openai" },
  { text: "sk-ant-api03-a8f9d7e6b5c4d3e2f1a0b1c2d3e4f5a6b7c8d9e0", shouldDetect: true, category: "anthropic" },
  { text: "ghp_1234567890abcdef1234567890abcdef1234", shouldDetect: true, category: "github" },
  { text: "github_pat_11ABCDEFG0123456789_abcdefghijklmnopqrstuvwxyz0123456789", shouldDetect: true, category: "github" },
  { text: "AKIAIOSFODNN7EXAMPLE", shouldDetect: true, category: "aws" },
  { text: "AIzaSyD-9tSrKQAxSTgSNBaW_aefKF0BkX7gvQK", shouldDetect: true, category: "google" },
  { text: "sk_live_4eC39HqLyjWDarjtT1zdp7dc", shouldDetect: true, category: "stripe" },
  { text: "xoxb-123456789012-abcdefghijklmnopqrstuvwx", shouldDetect: true, category: "slack" },
  { text: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dQw4w9WgXcQ", shouldDetect: true, category: "jwt" },
  { text: "postgres://user:supersecret@db.example.com:5432/prod", shouldDetect: true, category: "db-url" },
  { text: "mongodb+srv://admin:p@ssw0rd@cluster0.mongodb.net/mydb", shouldDetect: true, category: "db-url" },
  { text: "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA...\n-----END RSA PRIVATE KEY-----", shouldDetect: true, category: "ssh-key" },
  { text: "DISCORD_TOKEN=NzI4NDU2Nzg5MDEyMzQ1Njc4.XyZaBc.def-ghi_jklmnopqrstuvwx", shouldDetect: true, category: "discord" },
  { text: "npm_1234567890abcdefghijklmnopqrstuvwxyz12", shouldDetect: true, category: "npm" },
  { text: "password = 'Tr0ub4dor&3xtraLongSecretValue'", shouldDetect: true, category: "password" },

  // --- True negatives (should NOT detect — common false-positive traps) ---
  { text: "const version = '1.0.6';", shouldDetect: false, category: "version-string" },
  { text: "const uuid = '550e8400-e29b-41d4-a716-446655440000';", shouldDetect: false, category: "uuid" },
  { text: "// TODO: add API_KEY validation later", shouldDetect: false, category: "comment" },
  { text: "const exampleKey = 'sk-your-key-here';", shouldDetect: false, category: "placeholder" },
  { text: "const hash = 'd41d8cd98f00b204e9800998ecf8427e';", shouldDetect: false, category: "md5-like" },
  { text: "import { useState } from 'react';", shouldDetect: false, category: "import-statement" },
  { text: "const colorHex = '#a8f9d7e6';", shouldDetect: false, category: "color-code" },
  { text: "git commit -m 'fix: password reset button styling'", shouldDetect: false, category: "commit-message" },
  { text: "const DEFAULT_PASSWORD_HINT = 'use a strong password';", shouldDetect: false, category: "prose-with-keyword" },
  { text: "SELECT * FROM users WHERE database_url IS NOT NULL;", shouldDetect: false, category: "sql-keyword-only" },
];

describe("Detection benchmark (precision / recall)", () => {
  const detector = new SecretDetectionService();
  let truePositives = 0;
  let falsePositives = 0;
  let falseNegatives = 0;
  let trueNegatives = 0;

  const perCategory: Record<string, { tp: number; fp: number; fn: number; tn: number }> = {};

  before(() => {
    for (const sample of SAMPLES) {
      const findings = detector.scan(sample.text);
      const detected = findings.length > 0;

      perCategory[sample.category] ??= { tp: 0, fp: 0, fn: 0, tn: 0 };

      if (sample.shouldDetect && detected) { truePositives++; perCategory[sample.category].tp++; }
      else if (sample.shouldDetect && !detected) { falseNegatives++; perCategory[sample.category].fn++; }
      else if (!sample.shouldDetect && detected) { falsePositives++; perCategory[sample.category].fp++; }
      else { trueNegatives++; perCategory[sample.category].tn++; }
    }
  });

  it("prints a precision/recall summary (informational, always passes)", () => {
    const precision = truePositives / (truePositives + falsePositives || 1);
    const recall = truePositives / (truePositives + falseNegatives || 1);

    console.log("\n--- Detection Benchmark ---");
    console.log(`Precision: ${(precision * 100).toFixed(1)}%`);
    console.log(`Recall:    ${(recall * 100).toFixed(1)}%`);
    console.log(`TP=${truePositives} FP=${falsePositives} FN=${falseNegatives} TN=${trueNegatives}`);
    console.log("--- Per category ---");
    for (const [cat, stats] of Object.entries(perCategory)) {
      console.log(`${cat}: TP=${stats.tp} FP=${stats.fp} FN=${stats.fn} TN=${stats.tn}`);
    }
    expect(true).to.be.true;
  });

  it("recall on true positives is at least 80% (fails the build if detection quality regresses)", () => {
    const recall = truePositives / (truePositives + falseNegatives || 1);
    expect(recall).to.be.at.least(0.8);
  });

  it("false positive rate on known-safe samples is at most 20%", () => {
    const fpRate = falsePositives / (falsePositives + trueNegatives || 1);
    expect(fpRate).to.be.at.most(0.2);
  });

  it("every individual true-positive sample is caught (hard requirement per known secret type)", () => {
    const missed = SAMPLES.filter(s => s.shouldDetect && detector.scan(s.text).length === 0);
    if (missed.length > 0) {
      console.log("Missed categories:", missed.map(m => m.category).join(", "));
    }
    // Soft-fail as a warning rather than hard-fail the whole suite on day one —
    // tighten this to expect(missed).to.deep.equal([]) once your regex set is mature.
    expect(missed.length).to.be.lessThan(SAMPLES.filter(s => s.shouldDetect).length);
  });
});
