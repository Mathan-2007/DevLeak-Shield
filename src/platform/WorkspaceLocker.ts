import * as vscode from "vscode";
import { SecretDetectionService } from "../core/secrets/SecretDetectionService";
import { SecureVault } from "../core/vault/SecureVault";
import { SecretClassifier } from "../core/secrets/SecretClassifier";

/**
 * WorkspaceLocker: Vault-backed workspace secret masking
 *
 * Design:
 * - Scan all workspace files for secrets
 * - Store each secret in vault, get token reference
 * - Replace secret with token in files
 * - Supports reversible unlock with vault lookup
 * - Zero data loss - secrets stored securely in vault
 * - Survives restart - vault persists in SecretStorage
 *
 * Workflow:
 * lockWorkspace:
 *   - Find all secrets in workspace files
 *   - Store each in vault, get token
 *   - Replace secret with token in file
 *
 * unlockWorkspace:
 *   - Find all tokens in workspace files
 *   - Look up each in vault
 *   - Replace token with original secret
 */
export class WorkspaceLocker {
  private readonly detection = new SecretDetectionService();
  private readonly classifier = new SecretClassifier();
  private readonly LOCK_STATE_KEY = "devLeakShield.workspaceLockedState";

  constructor(
    private readonly secretStorage: vscode.SecretStorage,
    private readonly vault: SecureVault,
    private readonly secretDetectionService: SecretDetectionService
  ) {}

  /**
   * Lock workspace: Replace secrets with vault tokens
   */
  async lockWorkspace(): Promise<void> {
    const files = await vscode.workspace.findFiles(
      "**/*.{ts,tsx,js,jsx,json,md,env,txt,yml,yaml}",
      "**/{node_modules,out,dist,build,.git}/**"
    );
    const lockState: Map<string, { original: string; locked: string }> = new Map();

    for (const file of files) {
      try {
        const document = await vscode.workspace.openTextDocument(file);
        const original = document.getText();
        const result = this.secretDetectionService.detect(original, file.fsPath);

        if (result.findings.length === 0) continue;

        let lockedText = original;
        for (const finding of result.findings) {
          try {
            const classification = this.classifier.classify(finding.value);
            const vaultResult = await this.vault.store(finding.value, classification as any, finding.detection.risk, {
              source: "workspace_lock",
              filePath: file.fsPath,
            });

            lockedText = lockedText.replaceAll(finding.value, vaultResult.token);
          } catch (error) {
            console.error(`Failed to store secret in vault: ${error}`);
          }
        }

        if (lockedText !== original) {
          lockState.set(file.fsPath, { original, locked: lockedText });

          const edit = new vscode.WorkspaceEdit();
          edit.replace(
            file,
            new vscode.Range(document.positionAt(0), document.positionAt(original.length)),
            lockedText
          );
          await vscode.workspace.applyEdit(edit);
        }
      } catch (error) {
        console.error(`Error processing file ${file.fsPath}: ${error}`);
      }
    }

    // Save lock state for recovery
    await this.secretStorage.store(this.LOCK_STATE_KEY, JSON.stringify(Array.from(lockState.entries())));
  }

  /**
   * Unlock workspace: Restore secrets from vault tokens
   */
  async unlockWorkspace(): Promise<void> {
    const files = await vscode.workspace.findFiles(
      "**/*.{ts,tsx,js,jsx,json,md,env,txt,yml,yaml}",
      "**/{node_modules,out,dist,build,.git}/**"
    );

    for (const file of files) {
      try {
        const document = await vscode.workspace.openTextDocument(file);
        let text = document.getText();
        const tokens = this.extractTokens(text);

        if (tokens.length === 0) continue;

        for (const token of Array.from(new Set(tokens))) {
          try {
            const result = await this.vault.retrieve(token);
            if (result.found && result.secret) {
              text = text.replaceAll(token, result.secret);
            }
          } catch (error) {
            console.error(`Failed to retrieve secret for token ${token}: ${error}`);
          }
        }

        if (text !== document.getText()) {
          const edit = new vscode.WorkspaceEdit();
          edit.replace(
            file,
            new vscode.Range(document.positionAt(0), document.positionAt(document.getText().length)),
            text
          );
          await vscode.workspace.applyEdit(edit);
        }
      } catch (error) {
        console.error(`Error processing file ${file.fsPath}: ${error}`);
      }
    }

    // Clear lock state
    await this.secretStorage.store(this.LOCK_STATE_KEY, "");
  }

  /**
   * Extract vault reference tokens from text
   */
  private extractTokens(text: string): string[] {
    const matches = text.match(/DEVLEAKSHIELD_TOKEN_[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}/gi);
    return matches ?? [];
  }
}
