import { SecretDetectionService } from "./SecretDetectionService";

function escapeRegExp(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

export function maskOpenEditorSecrets(documentText: string, detector: SecretDetectionService): { masked: string; backup: string } {
  const lines = documentText.split(/\r?\n/);
  const separator = documentText.includes("\r\n") ? "\r\n" : "\n";

  const masked = lines
    .map((line) => {
      const lineResult = detector.detect(line);
      if (lineResult.findings.length === 0) {
        return line;
      }

      return lineResult.findings.reduce((currentLine, finding) => {
        const token = `[REDACTED_${finding.category}]`;
        return currentLine.replace(new RegExp(escapeRegExp(finding.value), "g"), token);
      }, line);
    })
    .join(separator);

  return { masked, backup: documentText };
}

export function restoreOpenEditorSecrets(documentUri: string, backupStore: Record<string, string>): string | null {
  return backupStore[documentUri] ?? null;
}
