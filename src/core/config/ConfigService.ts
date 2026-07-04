import * as fs from "fs";
import * as path from "path";

let vscodeRuntime: any;
try {
  vscodeRuntime = require("vscode");
} catch {
  vscodeRuntime = undefined;
}

export interface CustomPatternConfig {
  name: string;
  pattern: string;
  category?: string;
}

export class ConfigService {
  loadCustomPatterns(workspaceRoot?: string): CustomPatternConfig[] {
    const roots = this.getRoots(workspaceRoot);

    for (const root of roots) {
      for (const filename of [".devleakshield.yml", ".devleakshield.yaml"]) {
        const configPath = path.join(root, filename);
        try {
          if (fs.existsSync(configPath)) {
            return this.parse(fs.readFileSync(configPath, "utf8"));
          }
        } catch {
          // Continue to the next candidate path.
        }
      }
    }

    return [];
  }

  parse(content: string): CustomPatternConfig[] {
    const patterns: CustomPatternConfig[] = [];
    const lines = content.split(/\r?\n/);
    let activeSection: "customPatterns" | "rules" | null = null;
    let currentPattern: Partial<CustomPatternConfig> | undefined;

    for (const rawLine of lines) {
      const line = rawLine.trim();
      if (!line || line.startsWith("#")) continue;

      if (line === "customPatterns:" || line === "rules:") {
        activeSection = line === "customPatterns:" ? "customPatterns" : "rules";
        continue;
      }

      if (!activeSection) continue;

      if (line.startsWith("-")) {
        if (currentPattern) {
          patterns.push(this.normalizePattern(currentPattern));
        }
        currentPattern = {};
        const remainder = line.replace(/^-\s*/, "").trim();
        if (remainder) {
          const parsed = this.parseEntry(remainder);
          currentPattern = { ...currentPattern, ...parsed };
        }
        continue;
      }

      if (currentPattern) {
        const parsed = this.parseEntry(line);
        currentPattern = { ...currentPattern, ...parsed };
      }
    }

    if (currentPattern) {
      patterns.push(this.normalizePattern(currentPattern));
    }

    return patterns.filter((pattern) => pattern.name && pattern.pattern);
  }

  private parseEntry(line: string): Partial<CustomPatternConfig> {
    const match = line.match(/^(name|pattern|category):\s*(.+)$/);
    if (!match) {
      return {};
    }

    const [, key, rawValue] = match;
    const value = this.parseScalar(rawValue);

    if (key === "name" || key === "pattern" || key === "category") {
      return { [key]: value } as Partial<CustomPatternConfig>;
    }

    return {};
  }

  private normalizePattern(pattern: Partial<CustomPatternConfig>): CustomPatternConfig {
    return {
      name: pattern.name ?? "custom-pattern",
      pattern: pattern.pattern ?? "",
      category: pattern.category ?? "custom",
    };
  }

  private getRoots(workspaceRoot?: string): string[] {
    if (workspaceRoot) {
      return [path.resolve(workspaceRoot)];
    }

    if (vscodeRuntime?.workspace?.workspaceFolders?.length) {
      return vscodeRuntime.workspace.workspaceFolders.map((folder: any) => folder.uri.fsPath);
    }

    return [process.cwd()];
  }

  private parseScalar(rawValue: string): string {
    const trimmed = rawValue.trim();
    if ((trimmed.startsWith('"') && trimmed.endsWith('"')) || (trimmed.startsWith("'") && trimmed.endsWith("'"))) {
      return trimmed.slice(1, -1);
    }
    return trimmed;
  }
}
