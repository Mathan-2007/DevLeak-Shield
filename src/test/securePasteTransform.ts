import { CryptoService } from "./CryptoService";

export function securePasteTransform(
  clipboardText: string,
  tokenMap: Record<string, string>,
  cryptoService: CryptoService,
  key: string | Buffer
): string {
  const separator = clipboardText.includes("\r\n") ? "\r\n" : "\n";
  return clipboardText
    .split(separator)
    .map((line) =>
      line.replace(/\[REDACTED_([a-zA-Z0-9]+)\]/g, (match, tokenId: string) => {
        const payload = tokenMap[tokenId];
        if (!payload) {
          return match;
        }

        try {
          return cryptoService.decrypt(payload, key);
        } catch {
          return match;
        }
      })
    )
    .join(separator);
}
