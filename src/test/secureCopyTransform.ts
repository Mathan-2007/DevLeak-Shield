import { SecretDetectionService } from "./SecretDetectionService";
import { CryptoService } from "./CryptoService";

function escapeRegExp(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

export function secureCopyTransform(
  text: string,
  detectionService: SecretDetectionService,
  cryptoService: CryptoService,
  key: string | Buffer
): { output: string; findingsCount: number; tokenMap: Record<string, string> } {
  const lines = text.split(/\r?\n/);
  const tokenMap: Record<string, string> = {};
  let findingsCount = 0;
  const separator = text.includes("\r\n") ? "\r\n" : "\n";

  const output = lines
    .map((line) => {
      const lineResult = detectionService.detect(line);
      if (lineResult.findings.length === 0) {
        return line;
      }

      findingsCount += lineResult.findings.length;
      return lineResult.findings.reduce((currentLine, finding) => {
        const tokenId = `${Object.keys(tokenMap).length + 1}`;
        const encrypted = cryptoService.encrypt(finding.value, key);
        tokenMap[tokenId] = encrypted;
        const token = `[REDACTED_${tokenId}]`;
        return currentLine.replace(new RegExp(escapeRegExp(finding.value), "g"), token);
      }, line);
    })
    .join(separator);

  return { output, findingsCount, tokenMap };
}
