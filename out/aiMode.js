"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.maskOpenEditorSecrets = maskOpenEditorSecrets;
exports.restoreOpenEditorSecrets = restoreOpenEditorSecrets;
function escapeRegExp(value) {
    return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}
function maskOpenEditorSecrets(documentText, detector) {
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
function restoreOpenEditorSecrets(documentUri, backupStore) {
    return backupStore[documentUri] ?? null;
}
//# sourceMappingURL=aiMode.js.map