import * as vscode from "vscode";
import { AiPromptFirewall } from "../core/firewall/AiPromptFirewall";
import { PolicyEngine } from "../core/policies/PolicyEngine";
import { ClipboardAuditService } from "./ClipboardAuditService";
import { SecureCopyService } from "./SecureCopyService";
import { SecurePasteService } from "./SecurePasteService";
import { SecureVault } from "../core/vault/SecureVault";
import { NotificationService } from "../ui/NotificationService";
import { LoggingService } from "../ui/LoggingService";

export class ClipboardGuard {
  readonly copyService: SecureCopyService;
  readonly pasteService: SecurePasteService;
  readonly auditService: ClipboardAuditService;
  private secureCopyMode = false;

  constructor(
    private readonly policyEngine: PolicyEngine,
    private readonly firewall: AiPromptFirewall,
    private readonly vault: SecureVault
  ) {
    this.auditService = new ClipboardAuditService();
    this.copyService = new SecureCopyService(policyEngine, firewall, this.auditService, this.vault);
    this.pasteService = new SecurePasteService(this.auditService, this.vault);
  }

  setSecureCopyMode(enabled: boolean): void {
    this.secureCopyMode = enabled;
  }

  toggleSecureCopyMode(): boolean {
    this.secureCopyMode = !this.secureCopyMode;
    return this.secureCopyMode;
  }

  isSecureCopyEnabled(): boolean {
    return this.secureCopyMode;
  }

  async secureCopy(): Promise<void> {
    const editor = vscode.window.activeTextEditor;
    if (!editor) return;

    const text = editor.selection.isEmpty
      ? editor.document.lineAt(editor.selection.active.line).text
      : editor.document.getText(editor.selection);

    const result = await this.copyService.copy(text);

    if (result.blocked) {
      NotificationService.showError(`Secure copy blocked: ${result.reason}`);
      return;
    }

    await vscode.env.clipboard.writeText(result.text);
    LoggingService.log(
      `Secure copy: ${result.secretsProtected} secret(s) protected.`
    );
  }

  async securePaste(): Promise<void> {
    const editor = vscode.window.activeTextEditor;
    if (!editor) return;

    const clipboardText = await vscode.env.clipboard.readText();
    const result = await this.pasteService.paste(clipboardText);

    if (!result.success) {
      NotificationService.showError(`Secure paste blocked: ${result.reason}`);
      return;
    }

    const edit = new vscode.WorkspaceEdit();
    edit.replace(
      editor.document.uri,
      new vscode.Range(editor.selection.start, editor.selection.end),
      result.text
    );
    await vscode.workspace.applyEdit(edit);
    LoggingService.log(`Secure paste: ${result.decryptedCount} token(s) restored.`);
  }
  
  async encryptSelection(): Promise<void> {
    const editor = vscode.window.activeTextEditor;
    if (!editor || editor.selection.isEmpty) {
      NotificationService.showError("No text selected for encryption.");
      return;
    }

    const text = editor.document.getText(editor.selection);
    const result = await this.copyService.copy(text);

    if (result.blocked) {
      NotificationService.showError(`Encryption blocked: ${result.reason}`);
      return;
    }

    const edit = new vscode.WorkspaceEdit();
    edit.replace(editor.document.uri, editor.selection, result.text);
    await vscode.workspace.applyEdit(edit);
    LoggingService.log(`Encrypted ${result.secretsProtected} secret(s) in selection.`);
  }

  async decryptSelection(): Promise<void> {
    const editor = vscode.window.activeTextEditor;
    if (!editor || editor.selection.isEmpty) {
      NotificationService.showError("No text selected for decryption.");
      return;
    }

    const text = editor.document.getText(editor.selection);
    const result = await this.pasteService.paste(text);

    if (!result.success) {
      NotificationService.showError(`Decryption blocked: ${result.reason}`);
      return;
    }

    if (result.decryptedCount === 0) {
      LoggingService.log("No DevLeakShield tokens found in selection to decrypt.");
      return;
    }

    const edit = new vscode.WorkspaceEdit();
    edit.replace(editor.document.uri, editor.selection, result.text);
    await vscode.workspace.applyEdit(edit);
    LoggingService.log(`Decrypted ${result.decryptedCount} token(s) in selection.`);
  }

  getClipboardAuditSummary() {
    return this.auditService.getSummary();
  }
}
