import * as vscode from "vscode";
import { AiPromptFirewall } from "../core/firewall/AiPromptFirewall";
import { PolicyEngine } from "../core/policies/PolicyEngine";
import { ClipboardAuditService } from "./ClipboardAuditService";
import { SecureCopyService } from "./SecureCopyService";
import { SecurePasteService } from "./SecurePasteService";
import { SecureVault } from "../core/vault/SecureVault";

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

  toggleSecureCopyMode(): boolean {
    this.secureCopyMode = !this.secureCopyMode;
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
      vscode.window.showErrorMessage(`Secure copy blocked: ${result.reason}`);
      return;
    }

    await vscode.env.clipboard.writeText(result.text);
    vscode.window.showInformationMessage(
      `DevLeakShield: secure copy completed (${result.secretsProtected} secrets protected, risk=${result.risk.toFixed(2)})`
    );
  }

  async securePaste(): Promise<void> {
    const editor = vscode.window.activeTextEditor;
    if (!editor) return;

    const clipboardText = await vscode.env.clipboard.readText();
    const result = await this.pasteService.paste(clipboardText);

    if (!result.success) {
      vscode.window.showErrorMessage(`Secure paste blocked: ${result.reason}`);
      return;
    }

    if (result.decryptedCount === 0) {
      vscode.window.showInformationMessage("Clipboard contains no DevLeakShield tokens");
      return;
    }

    const edit = new vscode.WorkspaceEdit();
    edit.replace(
      editor.document.uri,
      new vscode.Range(editor.selection.start, editor.selection.end),
      result.text
    );
    await vscode.workspace.applyEdit(edit);
    vscode.window.showInformationMessage(`DevLeakShield: secure paste completed (${result.decryptedCount} tokens restored)`);
  }

  async encryptSelection(): Promise<void> {
    const editor = vscode.window.activeTextEditor;
    if (!editor || editor.selection.isEmpty) {
      vscode.window.showErrorMessage("No text selected");
      return;
    }

    const text = editor.document.getText(editor.selection);
    const result = await this.copyService.copy(text);

    if (result.blocked) {
      vscode.window.showErrorMessage(`Encryption blocked: ${result.reason}`);
      return;
    }

    const edit = new vscode.WorkspaceEdit();
    edit.replace(editor.document.uri, editor.selection, result.text);
    await vscode.workspace.applyEdit(edit);
    vscode.window.showInformationMessage(`Encrypted ${result.secretsProtected} secrets in selection`);
  }

  async decryptSelection(): Promise<void> {
    const editor = vscode.window.activeTextEditor;
    if (!editor || editor.selection.isEmpty) {
      vscode.window.showErrorMessage("No text selected");
      return;
    }

    const text = editor.document.getText(editor.selection);
    const result = await this.pasteService.paste(text);

    if (!result.success) {
      vscode.window.showErrorMessage(`Decryption blocked: ${result.reason}`);
      return;
    }

    if (result.decryptedCount === 0) {
      vscode.window.showInformationMessage("No DevLeakShield tokens found in selection");
      return;
    }

    const edit = new vscode.WorkspaceEdit();
    edit.replace(editor.document.uri, editor.selection, result.text);
    await vscode.workspace.applyEdit(edit);
    vscode.window.showInformationMessage(`Decrypted ${result.decryptedCount} tokens in selection`);
  }

  getClipboardAuditSummary() {
    return this.auditService.getSummary();
  }
}
