const fs = require("fs");
const path = require("path");
require("ts-node/register/transpile-only");
const { SecretDetectionService } = require("../src/core/secrets/SecretDetectionService");

const root = path.join(__dirname, "..", ".tmp", "benchmark");
fs.rmSync(root, { recursive: true, force: true });
fs.mkdirSync(root, { recursive: true });

const samples = [];
for (let index = 1; index <= 25; index += 1) {
  const fileName = `positive-${index}.txt`;
  const content = [
    `# Positive sample ${index}`,
    `OPENAI_API_KEY=sk-${"a".repeat(20 + (index % 5))}`,
    `GITHUB_PAT=github_pat_${"b".repeat(24)}`,
    `INTERNAL_${"C".repeat(20)}`,
  ].join("\n");
  fs.writeFileSync(path.join(root, fileName), content);
  samples.push({ fileName, expectedSecret: true });
}

for (let index = 1; index <= 25; index += 1) {
  const fileName = `negative-${index}.txt`;
  const content = [
    `# Benign sample ${index}`,
    "This note mentions a password hint but nothing secret is present.",
    "Use the placeholder token in the documentation example.",
    "No credentials are included here.",
  ].join("\n");
  fs.writeFileSync(path.join(root, fileName), content);
  samples.push({ fileName, expectedSecret: false });
}

const service = new SecretDetectionService([
  {
    name: "internal_api_key",
    pattern: "INTERNAL_[A-Z0-9]{20}",
    category: "api_key",
  },
]);

let truePositives = 0;
let falsePositives = 0;

for (const sample of samples) {
  const filePath = path.join(root, sample.fileName);
  const content = fs.readFileSync(filePath, "utf8");
  const result = service.detect(content, filePath);

  if (sample.expectedSecret) {
    if (result.findings.length > 0) {
      truePositives += 1;
    }
  } else if (result.findings.length > 0) {
    falsePositives += 1;
  }
}

const precision = ((truePositives / (truePositives + falsePositives)) * 100).toFixed(2);
console.log(JSON.stringify({
  totalFiles: samples.length,
  truePositives,
  falsePositives,
  precision: `${precision}%`,
}, null, 2));
