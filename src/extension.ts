import * as vscode from "vscode";
import { SessionManager } from "./core/session/SessionManager";
import { CommandRegistry } from "./commands/CommandRegistry";
import { StatusBarManager } from "./ui/StatusBarManager";
import { NotificationService } from "./ui/NotificationService";
import { LoggingService } from "./ui/LoggingService";

let statusBarManager: StatusBarManager | undefined;
let commandRegistry: CommandRegistry | undefined;
let clipboardGuard: import("./clipboard/ClipboardGuard").ClipboardGuard | undefined;
/**
 * DevLeakShield Extension: Production-grade secret protection platform
 *
 * Activation flow:
 * 1. Initialize SessionManager (load/generate master key from SecretStorage)
 * 2. Create PolicyEngine with security policies
 * 3. Initialize CommandRegistry and register all commands
 * 4. Set up status bar items
 * 5. Activate event listeners (clipboard analysis)
 *
 * Security architecture:
 * - Master key in VS Code SecretStorage (never plaintext)
 * - Vault-backed token system (tokens are references only)
 * - AES-256-GCM encryption with authentication
 * - Zero-trust design (no reversible data in tokens)
 */
export async function activate(context: vscode.ExtensionContext) {
  try {
    // Initialize status bar
    statusBarManager = new StatusBarManager(context);

    // Initialize session manager and master key
    const sessionManager = new SessionManager(context.secrets);
    await sessionManager.initialize();
    console.log("DevLeakShield: Master key initialized in SecretStorage");

    // Initialize command registry
    commandRegistry = new CommandRegistry(context, sessionManager, statusBarManager);
    await commandRegistry.initializeServices();
    commandRegistry.registerCommands();
    clipboardGuard = commandRegistry.getClipboardGuard();
    console.log("DevLeakShield: Commands registered");

    // Set up status bar
    // Status bar items are now created inside CommandRegistry

    // --- Interception Logic for Copy/Paste ---

    context.subscriptions.push(
      vscode.commands.registerCommand('devleakshield.smartCopy', async () => {
        if (clipboardGuard?.isSecureCopyEnabled()) {
          await clipboardGuard.secureCopy();
        } else {
          await vscode.commands.executeCommand('editor.action.clipboardCopyAction');
        }
      })
    );

    context.subscriptions.push(
      vscode.commands.registerCommand('devleakshield.smartPaste', async (args) => {
        try {
          const clipboardText = await vscode.env.clipboard.readText();
          if (!clipboardGuard) {
            await vscode.commands.executeCommand('editor.action.clipboardPasteAction', args);
            return;
          }

          const pasteResult = await clipboardGuard.pasteService.paste(clipboardText);

          if (!pasteResult.success) {
            NotificationService.showError(`Smart Paste blocked: ${pasteResult.reason}`);
            return;
          }

          if (pasteResult.decryptedCount > 0) {
            // We handled it, so paste the restored text
            const editor = vscode.window.activeTextEditor;
            if (editor) {
              await editor.edit(editBuilder => {
                editBuilder.replace(editor.selection, pasteResult.text);
              });
              LoggingService.log(`Restored ${pasteResult.decryptedCount} secret(s) on paste.`);
            }
          } else {
            // No tokens, fall back to default paste
            await vscode.commands.executeCommand('editor.action.clipboardPasteAction', args);
          }
        } catch (error) {
          NotificationService.showError(`Smart Paste failed: ${error instanceof Error ? error.message : String(error)}`);
          // Fallback to default paste on error
          await vscode.commands.executeCommand('editor.action.clipboardPasteAction', args);
        }
      }),
    );

    console.log("✅ DevLeakShield activated as enterprise-grade extension with zero-trust vault architecture.");
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    console.error(`❌ DevLeakShield activation failed: ${message}`);
    NotificationService.showError(`DevLeakShield initialization failed: ${message}`);
  }
}

export function deactivate(): void {
  statusBarManager?.dispose();
  LoggingService.dispose();
  console.log("DevLeakShield deactivated.");
}
