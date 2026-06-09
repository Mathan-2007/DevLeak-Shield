"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.ClipboardGuard = void 0;
const vscode = require("vscode");
const ClipboardAuditService_1 = require("./ClipboardAuditService");
const SecureCopyService_1 = require("./SecureCopyService");
const SecurePasteService_1 = require("./SecurePasteService");
const NotificationService_1 = require("../ui/NotificationService");
const LoggingService_1 = require("../ui/LoggingService");
class ClipboardGuard {
    constructor(policyEngine, firewall, vault) {
        this.policyEngine = policyEngine;
        this.firewall = firewall;
        this.vault = vault;
        this.secureCopyMode = false;
        this.auditService = new ClipboardAuditService_1.ClipboardAuditService();
        this.copyService = new SecureCopyService_1.SecureCopyService(policyEngine, firewall, this.auditService, this.vault);
        this.pasteService = new SecurePasteService_1.SecurePasteService(this.auditService, this.vault);
    }
    setSecureCopyMode(enabled) {
        this.secureCopyMode = enabled;
    }
    toggleSecureCopyMode() {
        this.secureCopyMode = !this.secureCopyMode;
        return this.secureCopyMode;
    }
    isSecureCopyEnabled() {
        return this.secureCopyMode;
    }
    async secureCopy() {
        const editor = vscode.window.activeTextEditor;
        if (!editor)
            return;
        const text = editor.selection.isEmpty
            ? editor.document.lineAt(editor.selection.active.line).text
            : editor.document.getText(editor.selection);
        const result = await this.copyService.copy(text);
        if (result.blocked) {
            NotificationService_1.NotificationService.showError(`Secure copy blocked: ${result.reason}`);
            return;
        }
        await vscode.env.clipboard.writeText(result.text);
        LoggingService_1.LoggingService.log(`Secure copy: ${result.secretsProtected} secret(s) protected.`);
    }
    async securePaste() {
        const editor = vscode.window.activeTextEditor;
        if (!editor)
            return;
        const clipboardText = await vscode.env.clipboard.readText();
        const result = await this.pasteService.paste(clipboardText);
        if (!result.success) {
            NotificationService_1.NotificationService.showError(`Secure paste blocked: ${result.reason}`);
            return;
        }
        const edit = new vscode.WorkspaceEdit();
        edit.replace(editor.document.uri, new vscode.Range(editor.selection.start, editor.selection.end), result.text);
        await vscode.workspace.applyEdit(edit);
        LoggingService_1.LoggingService.log(`Secure paste: ${result.decryptedCount} token(s) restored.`);
    }
    async encryptSelection() {
        const editor = vscode.window.activeTextEditor;
        if (!editor || editor.selection.isEmpty) {
            NotificationService_1.NotificationService.showError("No text selected for encryption.");
            return;
        }
        const text = editor.document.getText(editor.selection);
        const result = await this.copyService.copy(text);
        if (result.blocked) {
            NotificationService_1.NotificationService.showError(`Encryption blocked: ${result.reason}`);
            return;
        }
        const edit = new vscode.WorkspaceEdit();
        edit.replace(editor.document.uri, editor.selection, result.text);
        await vscode.workspace.applyEdit(edit);
        LoggingService_1.LoggingService.log(`Encrypted ${result.secretsProtected} secret(s) in selection.`);
    }
    async decryptSelection() {
        const editor = vscode.window.activeTextEditor;
        if (!editor || editor.selection.isEmpty) {
            NotificationService_1.NotificationService.showError("No text selected for decryption.");
            return;
        }
        const text = editor.document.getText(editor.selection);
        const result = await this.pasteService.paste(text);
        if (!result.success) {
            NotificationService_1.NotificationService.showError(`Decryption blocked: ${result.reason}`);
            return;
        }
        if (result.decryptedCount === 0) {
            LoggingService_1.LoggingService.log("No DevLeakShield tokens found in selection to decrypt.");
            return;
        }
        const edit = new vscode.WorkspaceEdit();
        edit.replace(editor.document.uri, editor.selection, result.text);
        await vscode.workspace.applyEdit(edit);
        LoggingService_1.LoggingService.log(`Decrypted ${result.decryptedCount} token(s) in selection.`);
    }
    getClipboardAuditSummary() {
        return this.auditService.getSummary();
    }
}
exports.ClipboardGuard = ClipboardGuard;
//# sourceMappingURL=ClipboardGuard.js.map