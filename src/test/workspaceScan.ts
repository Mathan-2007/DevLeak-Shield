import * as fs from "fs";
import * as path from "path";
import { SecretDetectionService } from "./SecretDetectionService";

export function scanWorkspaceForSecrets(rootPath: string, detector: SecretDetectionService, maxFiles = 50) {
  if (!rootPath || !fs.existsSync(rootPath) || !fs.statSync(rootPath).isDirectory()) {
    return [];
  }

  const findings: Array<any> = [];
  const files = listFiles(rootPath).filter((file) => isScannableFile(file));

  for (const file of files.slice(0, maxFiles)) {
    try {
      const content = fs.readFileSync(file, "utf8");
      const result = detector.detect(content, file);
      findings.push(...result.findings);
    } catch {
      // Skip unreadable or invalid files.
    }
  }

  return findings;
}

function listFiles(rootPath: string): string[] {
  const entries = fs.readdirSync(rootPath, { withFileTypes: true });
  const files: string[] = [];

  for (const entry of entries) {
    const fullPath = path.join(rootPath, entry.name);
    if (entry.isDirectory()) {
      if (["node_modules", "out", "dist", "build", ".git", "venv", "env"].includes(entry.name)) {
        continue;
      }
      files.push(...listFiles(fullPath));
    } else if (entry.isFile()) {
      files.push(fullPath);
    }
  }

  return files;
}

function isScannableFile(filePath: string): boolean {
  const extension = path.extname(filePath).toLowerCase();
  const allowed = [
    ".ts",
    ".tsx",
    ".js",
    ".jsx",
    ".py",
    ".java",
    ".go",
    ".rb",
    ".sh",
    ".bash",
    ".json",
    ".md",
    ".env",
    ".txt",
    ".yml",
    ".yaml",
    ".xml",
    ".gradle",
    ".properties",
    ".ini",
    ".conf",
    ".toml",
  ];

  return allowed.includes(extension) || path.basename(filePath) === ".env";
}
