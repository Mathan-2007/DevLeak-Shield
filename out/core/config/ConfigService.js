"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.ConfigService = void 0;
const vscode = require("vscode");
class ConfigService {
    async loadCustomPatterns(workspaceRoot) {
        const roots = workspaceRoot
            ? [vscode.Uri.file(workspaceRoot)]
            : (vscode.workspace.workspaceFolders ?? []).map((folder) => folder.uri);
        for (const root of roots) {
            for (const filename of [".devleakshield.yml", ".devleakshield.yaml"]) {
                const configPath = vscode.Uri.joinPath(root, filename);
                try {
                    const content = await vscode.workspace.fs.readFile(configPath);
                    return this.parse(content.toString());
                }
                catch {
                    // Continue to the next candidate path.
                }
            }
        }
        return [];
    }
    parse(content) {
        const patterns = [];
        const lines = content.split(/\r?\n/);
        let inCustomPatterns = false;
        let currentPattern;
        for (const rawLine of lines) {
            const line = rawLine.trim();
            if (!line || line.startsWith("#"))
                continue;
            if (line === "customPatterns:") {
                inCustomPatterns = true;
                continue;
            }
            if (!inCustomPatterns)
                continue;
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
    parseEntry(line) {
        const match = line.match(/^(name|pattern|category):\s*(.+)$/);
        if (!match) {
            return {};
        }
        const [, key, rawValue] = match;
        const value = this.parseScalar(rawValue);
        if (key === "name" || key === "pattern" || key === "category") {
            return { [key]: value };
        }
        return {};
    }
    normalizePattern(pattern) {
        return {
            name: pattern.name ?? "custom-pattern",
            pattern: pattern.pattern ?? "",
            category: pattern.category ?? "custom",
        };
    }
    getRoots(workspaceRoot) {
        if (workspaceRoot) {
            return [path.resolve(workspaceRoot)];
        }
        if (vscodeRuntime?.workspace?.workspaceFolders?.length) {
            return vscodeRuntime.workspace.workspaceFolders.map((folder) => folder.uri.fsPath);
        }
        return [process.cwd()];
    }
    parseScalar(rawValue) {
        const trimmed = rawValue.trim();
        if ((trimmed.startsWith('"') && trimmed.endsWith('"')) || (trimmed.startsWith("'") && trimmed.endsWith("'"))) {
            return trimmed.slice(1, -1);
        }
        return trimmed;
    }
}
exports.ConfigService = ConfigService;
//# sourceMappingURL=ConfigService.js.map