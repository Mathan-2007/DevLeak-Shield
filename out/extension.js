"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.activate = activate;
exports.deactivate = deactivate;
const vscode = require("vscode");
const SessionManager_1 = require("./core/session/SessionManager");
const CommandRegistry_1 = require("./commands/CommandRegistry");
const StatusBarManager_1 = require("./ui/StatusBarManager");
const NotificationService_1 = require("./ui/NotificationService");
const LoggingService_1 = require("./ui/LoggingService");
let statusBarManager;
let commandRegistry;
let clipboardGuard; // Simplified for interception logic
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
async function activate(context) {
    try {
        // Initialize status bar
        statusBarManager = new StatusBarManager_1.StatusBarManager(context);
        // Initialize session manager and master key
        const sessionManager = new SessionManager_1.SessionManager(context.secrets);
        await sessionManager.initialize();
        console.log("DevLeakShield: Master key initialized in SecretStorage");
        // Initialize command registry
        commandRegistry = new CommandRegistry_1.CommandRegistry(context, sessionManager, statusBarManager);
        await commandRegistry.initializeServices();
        commandRegistry.registerCommands();
        clipboardGuard = commandRegistry.clipboardGuard;
        console.log("DevLeakShield: Commands registered");
        // Set up status bar
        // Status bar items are now created inside CommandRegistry
        // --- Interception Logic for Copy/Paste ---
        context.subscriptions.push(vscode.commands.registerCommand('devleakshield.smartCopy', async () => {
            if (clipboardGuard?.isSecureCopyEnabled()) {
                await clipboardGuard.secureCopy();
            }
            else {
                await vscode.commands.executeCommand('editor.action.clipboardCopyAction');
            }
        }));
        context.subscriptions.push(vscode.commands.registerCommand('devleakshield.smartPaste', async (args) => {
            try {
                const clipboardText = await vscode.env.clipboard.readText();
                const pasteResult = await clipboardGuard.pasteService.paste(clipboardText);
                if (pasteResult.decryptedCount > 0) {
                    // We handled it, so paste the restored text
                    const editor = vscode.window.activeTextEditor;
                    if (editor) {
                        editor.edit(editBuilder => {
                            editBuilder.replace(editor.selection, pasteResult.text);
                        });
                        LoggingService_1.LoggingService.log(`Restored ${pasteResult.decryptedCount} secret(s) on paste.`);
                    }
                }
                else {
                    // No tokens, fall back to default paste
                    await vscode.commands.executeCommand('editor.action.clipboardPasteAction', args);
                }
            }
            catch (error) {
                NotificationService_1.NotificationService.showError(`Smart Paste failed: ${error instanceof Error ? error.message : String(error)}`);
                // Fallback to default paste on error
                await vscode.commands.executeCommand('editor.action.clipboardPasteAction', args);
            }
        }));
        console.log("✅ DevLeakShield activated as enterprise-grade extension with zero-trust vault architecture.");
    }
    catch (error) {
        const message = error instanceof Error ? error.message : String(error);
        console.error(`❌ DevLeakShield activation failed: ${message}`);
        NotificationService_1.NotificationService.showError(`DevLeakShield initialization failed: ${message}`);
    }
}
function deactivate() {
    statusBarManager?.dispose();
    LoggingService_1.LoggingService.dispose();
    console.log("DevLeakShield deactivated.");
}
//# sourceMappingURL=extension.js.map