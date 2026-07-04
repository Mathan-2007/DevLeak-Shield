"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.securePasteTransform = securePasteTransform;
function securePasteTransform(clipboardText, tokenMap, cryptoService, key) {
    const separator = clipboardText.includes("\r\n") ? "\r\n" : "\n";
    return clipboardText
        .split(separator)
        .map((line) => line.replace(/\[REDACTED_([a-zA-Z0-9]+)\]/g, (match, tokenId) => {
        const payload = tokenMap[tokenId];
        if (!payload) {
            return match;
        }
        try {
            return cryptoService.decrypt(payload, key);
        }
        catch {
            return match;
        }
    }))
        .join(separator);
}
//# sourceMappingURL=securePasteTransform.js.map