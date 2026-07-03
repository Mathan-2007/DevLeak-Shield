"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.activate = activate;
exports.deactivate = deactivate;
const vscode = require("vscode");
const CryptoService_1 = require("./core/crypto/CryptoService");
const SecretDetectionService_1 = require("./core/secrets/SecretDetectionService");
const SecretClassifier_1 = require("./core/secrets/SecretClassifier");
const ReportGenerator_1 = require("./core/reports/ReportGenerator");
const NotificationService_1 = require("./ui/NotificationService");
const LoggingService_1 = require("./ui/LoggingService");
const SECURE_COPY_STATE_KEY = "devleakshield.secureCopyState";
const AI_MODE_STATE_KEY = "devleakshield.aiModeState";
const SESSION_KEY_STATE_KEY = "devleakshield.sessionKey";
const COPY_TOKEN_PREFIX = "HIDDEN_SECRET_DO_NOT_DECODE_";
const COPY_TOKEN_REGEX = /HIDDEN_SECRET_DO_NOT_DECODE_([A-Za-z0-9+/=\-_]+)(?::([A-Za-z0-9+/=\-_]+))?/g;
let secretKey;
let secureCopyEnabled = false;
let aiModeEnabled = false;
let secureCopyStatusBar;
let aiModeStatusBar;
let aiModeBackup = new Map();
const secretDetectionService = new SecretDetectionService_1.SecretDetectionService();
const secretClassifier = new SecretClassifier_1.SecretClassifier();
const reportGenerator = new ReportGenerator_1.ReportGenerator();
/**
 * DevLeakShield Extension - Simplified 3-Feature Edition
 *
 * Features:
 * 1. Toggle Secure Copy Mode - Encrypts secrets to vault tokens on copy
 * 2. Toggle AI Mode - Masks workspace secrets
 * 3. Generate Security Report - Scans and reports detected secrets
 *
 * Architecture:
 * - A persistent session key is generated once and stored (enables decrypt across launches)
 * - AES-256-GCM encryption is used for secure copy tokens
 * - Secure copy encodes only classified secrets
 */
async function activate(context) {
    try {
        console.log("🔐 DevLeakShield: Initializing...");
        // Load or generate session key (persist across launches for decrypt compatibility)
        const storedKey = await context.secrets.get(SESSION_KEY_STATE_KEY);
        if (storedKey) {
            secretKey = Buffer.from(storedKey, "base64");
            console.log("✅ Session key restored from storage");
        }
        else {
            secretKey = generateSessionKey();
            await context.secrets.store(SESSION_KEY_STATE_KEY, secretKey.toString("base64"));
            console.log("✅ New session key generated and stored");
        }
        // Restore persisted states
        secureCopyEnabled = (await context.secrets.get(SECURE_COPY_STATE_KEY)) === "true";
        aiModeEnabled = (await context.secrets.get(AI_MODE_STATE_KEY)) === "true";
        // Create status bar items
        secureCopyStatusBar = vscode.window.createStatusBarItem("devleakshield.secureCopy", vscode.StatusBarAlignment.Left, 98);
        secureCopyStatusBar.command = "devleakshield.toggleSecureCopyMode";
        updateSecureCopyStatusBar();
        secureCopyStatusBar.show();
        context.subscriptions.push(secureCopyStatusBar);
        aiModeStatusBar = vscode.window.createStatusBarItem("devleakshield.aiMode", vscode.StatusBarAlignment.Left, 97);
        aiModeStatusBar.command = "devleakshield.toggleAiMode";
        updateAiModeStatusBar();
        aiModeStatusBar.show();
        context.subscriptions.push(aiModeStatusBar);
        // Register commands
        context.subscriptions.push(vscode.commands.registerCommand("devleakshield.toggleSecureCopyMode", async () => {
            secureCopyEnabled = !secureCopyEnabled;
            await context.secrets.store(SECURE_COPY_STATE_KEY, String(secureCopyEnabled));
            updateSecureCopyStatusBar();
            NotificationService_1.NotificationService.showInformation(`Secure Copy ${secureCopyEnabled ? "enabled" : "disabled"}.`);
            LoggingService_1.LoggingService.log(`Secure Copy ${secureCopyEnabled ? "enabled" : "disabled"}.`);
        }));
        context.subscriptions.push(vscode.commands.registerCommand("devleakshield.smartCopy", async () => {
            try {
                if (!secureCopyEnabled) {
                    await vscode.commands.executeCommand("editor.action.clipboardCopyAction");
                    return;
                }
                const editor = vscode.window.activeTextEditor;
                if (!editor) {
                    await vscode.commands.executeCommand("editor.action.clipboardCopyAction");
                    return;
                }
                const selection = editor.document.getText(editor.selection);
                if (!selection.trim()) {
                    await vscode.commands.executeCommand("editor.action.clipboardCopyAction");
                    return;
                }
                let secretLines = 0;
                const output = selection
                    .split(/\r?\n/)
                    .map((line) => {
                    const lineResult = secretDetectionService.detect(line);
                    if (lineResult.findings.length === 0) {
                        return line;
                    }
                    secretLines += 1;
                    return lineResult.findings.reduce((currentLine, finding) => {
                        const escaped = escapeRegExp(finding.value);
                        const encrypted = CryptoService_1.CryptoService.encrypt(finding.value, secretKey);
                        const token = `${COPY_TOKEN_PREFIX}${encrypted}`;
                        return currentLine.replace(new RegExp(escaped, "g"), token);
                    }, line);
                })
                    .join(editor.document.eol === vscode.EndOfLine.CRLF ? "\r\n" : "\n");
                if (secretLines === 0) {
                    await vscode.commands.executeCommand("editor.action.clipboardCopyAction");
                    NotificationService_1.NotificationService.showInformation("Secure Copy is enabled but selection is not classified as a secret.");
                    return;
                }
                await vscode.env.clipboard.writeText(output);
                NotificationService_1.NotificationService.showInformation(`Secret selection encoded and copied securely (${secretLines} line(s)).`);
                LoggingService_1.LoggingService.log(`Secure copy encoded selection with ${secretLines} secret line(s).`);
            }
            catch (error) {
                NotificationService_1.NotificationService.showError(`Secure copy failed: ${error instanceof Error ? error.message : String(error)}`);
                await vscode.commands.executeCommand("editor.action.clipboardCopyAction");
            }
        }));
        context.subscriptions.push(vscode.commands.registerCommand("devleakshield.smartPaste", async () => {
            try {
                const text = await vscode.env.clipboard.readText();
                const decrypted = tryDecryptClipboardToken(text);
                if (decrypted !== undefined) {
                    const editor = vscode.window.activeTextEditor;
                    if (editor) {
                        await editor.edit((editBuilder) => {
                            editBuilder.replace(editor.selection, decrypted);
                        });
                        NotificationService_1.NotificationService.showInformation("Secure clipboard content decrypted on paste.");
                        LoggingService_1.LoggingService.log("Secure paste completed.");
                        return;
                    }
                }
                await vscode.commands.executeCommand("editor.action.clipboardPasteAction");
            }
            catch (error) {
                NotificationService_1.NotificationService.showError(`Secure paste failed: ${error instanceof Error ? error.message : String(error)}`);
                await vscode.commands.executeCommand("editor.action.clipboardPasteAction");
            }
        }));
        context.subscriptions.push(vscode.commands.registerCommand("devleakshield.toggleAiMode", async () => {
            try {
                aiModeEnabled = !aiModeEnabled;
                aiModeStatusBar.text = "$(loading~spin) AI Mode...";
                aiModeStatusBar.show();
                await vscode.window.withProgress({
                    location: vscode.ProgressLocation.Notification,
                    title: aiModeEnabled ? "AI Mode analyzing secrets..." : "AI Mode restoring editor text...",
                    cancellable: false,
                }, async (progress) => {
                    if (aiModeEnabled) {
                        await maskOpenEditorSecrets(progress);
                    }
                    else {
                        await restoreOpenEditorContent(progress);
                    }
                });
                await context.secrets.store(AI_MODE_STATE_KEY, String(aiModeEnabled));
                updateAiModeStatusBar();
                NotificationService_1.NotificationService.showInformation(aiModeEnabled
                    ? "AI Mode enabled. Open editor secrets analyzed and encoded."
                    : "AI Mode disabled. Open editor content restored when possible.");
                LoggingService_1.LoggingService.log(`AI Mode ${aiModeEnabled ? "enabled" : "disabled"}`);
            }
            catch (error) {
                NotificationService_1.NotificationService.showError(`AI Mode toggle failed: ${error instanceof Error ? error.message : String(error)}`);
                aiModeEnabled = !aiModeEnabled;
                updateAiModeStatusBar();
            }
        }));
        context.subscriptions.push(vscode.commands.registerCommand("devleakshield.generateSecurityReport", async () => {
            try {
                vscode.window.withProgress({ location: vscode.ProgressLocation.Notification, title: "Scanning workspace for secrets..." }, async (progress) => {
                    const findings = await scanWorkspaceForSecrets();
                    const report = reportGenerator.generateJson(findings);
                    const doc = await vscode.workspace.openTextDocument({ content: report, language: "json" });
                    await vscode.window.showTextDocument(doc, { preview: false });
                    LoggingService_1.LoggingService.log(`Report generated with ${findings.length} finding(s)`);
                });
            }
            catch (error) {
                NotificationService_1.NotificationService.showError(`Report generation failed: ${error instanceof Error ? error.message : String(error)}`);
            }
        }));
        console.log("✅ DevLeakShield: 3-Feature edition activated (Secure Copy | AI Mode | Report)");
    }
    catch (error) {
        const message = error instanceof Error ? error.message : String(error);
        console.error(`❌ DevLeakShield activation failed: ${message}`);
        NotificationService_1.NotificationService.showError(`DevLeakShield initialization failed: ${message}`);
    }
}
function deactivate() {
    LoggingService_1.LoggingService.dispose();
    console.log("✅ DevLeakShield deactivated");
}
/**
 * Generate a fresh random session key on every activation.
 */
function generateSessionKey() {
    return CryptoService_1.CryptoService.generateKey();
}
function updateSecureCopyStatusBar() {
    secureCopyStatusBar.text = secureCopyEnabled
        ? "$(circle-filled) Secure Copy"
        : "$(circle-large-outline) Secure Copy";
    secureCopyStatusBar.tooltip = secureCopyEnabled
        ? "Secure Copy is ON. Secrets will be encrypted on copy."
        : "Secure Copy is OFF. Click to enable.";
}
function updateAiModeStatusBar() {
    aiModeStatusBar.text = aiModeEnabled
        ? "$(circle-filled) AI Mode"
        : "$(circle-large-outline) AI Mode";
    aiModeStatusBar.tooltip = aiModeEnabled
        ? "AI Mode is ON. Workspace secrets are masked."
        : "AI Mode is OFF. Click to enable.";
}
function tryDecryptClipboardToken(text) {
    const normalized = text.replace(/\r\n/g, "\n");
    const lines = normalized.split("\n");
    let decryptedAny = false;
    const decoded = lines
        .map((line) => {
        return line.replace(COPY_TOKEN_REGEX, (match, group1, group2) => {
            const payload = group2 ? `${group1}${group2}` : group1;
            try {
                decryptedAny = true;
                return CryptoService_1.CryptoService.decrypt(payload, secretKey);
            }
            catch {
                return match; // return original match if decrypt fails
            }
        });
    })
        .join("\n");
    return decryptedAny ? decoded : undefined;
}
async function scanWorkspaceForSecrets() {
    const files = await vscode.workspace.findFiles("**/*.{ts,tsx,js,jsx,py,java,go,rb,sh,bash,json,md,env,txt,yml,yaml,xml,gradle,properties,ini,conf,toml}", "**/{node_modules,out,dist,build,.git,venv,env}/**");
    const findings = [];
    await Promise.all(files.slice(0, 50).map(async (file) => {
        try {
            const content = await vscode.workspace.fs.readFile(file);
            const text = content.toString();
            const result = secretDetectionService.detect(text, file.fsPath);
            findings.push(...result.findings);
        }
        catch (error) {
            // Skip unreadable files
        }
    }));
    return findings;
}
async function maskOpenEditorSecrets(progress) {
    const editors = vscode.window.visibleTextEditors.filter((editor) => !editor.document.isClosed);
    const total = editors.length;
    let processed = 0;
    for (const editor of editors) {
        const text = editor.document.getText();
        const result = secretDetectionService.detect(text, editor.document.fileName);
        if (result.findings.length > 0) {
            aiModeBackup.set(editor.document.uri.toString(), text);
            const encodedText = text
                .split(/\r?\n/)
                .map((line) => {
                const lineResult = secretDetectionService.detect(line, editor.document.fileName);
                if (lineResult.findings.length === 0) {
                    return line;
                }
                return lineResult.findings.reduce((currentLine, finding) => {
                    const escaped = escapeRegExp(finding.value);
                    const encrypted = CryptoService_1.CryptoService.encrypt(finding.value, secretKey);
                    const token = `${COPY_TOKEN_PREFIX}${encrypted}`;
                    return currentLine.replace(new RegExp(escaped, "g"), token);
                }, line);
            })
                .join(editor.document.eol === vscode.EndOfLine.CRLF ? "\r\n" : "\n");
            const fullRange = new vscode.Range(editor.document.positionAt(0), editor.document.positionAt(text.length));
            await editor.edit((editBuilder) => {
                editBuilder.replace(fullRange, encodedText);
            });
        }
        processed += 1;
        progress.report({ message: `Analyzed ${processed}/${total} open editor(s)` });
    }
}
async function restoreOpenEditorContent(progress) {
    const entries = Array.from(aiModeBackup.entries());
    const total = entries.length;
    let processed = 0;
    for (const [uriString, originalText] of entries) {
        const uri = vscode.Uri.parse(uriString);
        const document = await vscode.workspace.openTextDocument(uri);
        const editor = vscode.window.visibleTextEditors.find((item) => item.document.uri.toString() === uriString);
        if (editor && !document.isClosed) {
            const fullRange = new vscode.Range(editor.document.positionAt(0), editor.document.positionAt(editor.document.getText().length));
            await editor.edit((editBuilder) => {
                editBuilder.replace(fullRange, originalText);
            });
        }
        else if (!editor && !document.isClosed) {
            const edit = await vscode.window.showTextDocument(document, { preview: false });
            const fullRange = new vscode.Range(document.positionAt(0), document.positionAt(document.getText().length));
            await edit.edit((editBuilder) => {
                editBuilder.replace(fullRange, originalText);
            });
        }
        processed += 1;
        progress.report({ message: `Restored ${processed}/${total} file(s)` });
    }
    aiModeBackup.clear();
}
function escapeRegExp(value) {
    return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}
//# sourceMappingURL=extension.js.map