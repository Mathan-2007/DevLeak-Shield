"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.secureCopyTransform = secureCopyTransform;
function escapeRegExp(value) {
    return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}
function secureCopyTransform(text, detectionService, cryptoService, key) {
    const lines = text.split(/\r?\n/);
    const tokenMap = {};
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
//# sourceMappingURL=secureCopyTransform.js.map