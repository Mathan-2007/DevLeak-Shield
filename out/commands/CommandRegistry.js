"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.CommandRegistry = void 0;
const vscode = require("vscode");
const AiPromptFirewall_1 = require("../core/firewall/AiPromptFirewall");
const PolicyEngine_1 = require("../core/policies/PolicyEngine");
const ReportGenerator_1 = require("../core/reports/ReportGenerator");
const SecurityDashboardService_1 = require("../core/dashboard/SecurityDashboardService");
const SecureVault_1 = require("../core/vault/SecureVault");
const WorkspaceLocker_1 = require("../platform/WorkspaceLocker");
const SecretDetectionService_1 = require("../core/secrets/SecretDetectionService");
const ClipboardGuard_1 = require("../clipboard/ClipboardGuard");
const GitSecurityScanner_1 = require("../core/git/GitSecurityScanner");
const NotificationService_1 = require("../ui/NotificationService");
const LoggingService_1 = require("../ui/LoggingService");
class CommandRegistry {
    constructor(context, sessionManager, statusBarManager) {
        this.context = context;
        this.sessionManager = sessionManager;
        this.statusBarManager = statusBarManager;
        this.dashboard = new SecurityDashboardService_1.SecurityDashboardService();
        this.reportGenerator = new ReportGenerator_1.ReportGenerator();
        this.secretDetectionService = new SecretDetectionService_1.SecretDetectionService();
        this.aiModeEnabled = false;
        // Initialize policy engine with default policies
        this.policyEngine = new PolicyEngine_1.PolicyEngine(CommandRegistry.DEFAULT_POLICIES);
    }
    async initializeServices() {
        // Load policies from configuration
        const config = vscode.workspace.getConfiguration("devLeakShield");
        const configuredPolicies = config.get("policies");
        const policies = configuredPolicies && configuredPolicies.length > 0
            ? configuredPolicies
            : CommandRegistry.DEFAULT_POLICIES;
        this.policyEngine = new PolicyEngine_1.PolicyEngine(policies);
        this.firewall = new AiPromptFirewall_1.AiPromptFirewall(this.policyEngine);
        const masterKey = this.sessionManager.getMasterKey();
        // Initialize vault and clipboard guard
        this.secureVault = new SecureVault_1.SecureVault(this.context.secrets, masterKey);
        await this.secureVault.initialize();
        this.clipboardGuard = new ClipboardGuard_1.ClipboardGuard(this.policyEngine, this.firewall, this.secureVault);
        this.workspaceLocker = new WorkspaceLocker_1.WorkspaceLocker(this.context.secrets, this.secureVault, this.secretDetectionService);
        // Restore persisted states
        const secureCopyState = await this.context.secrets.get(CommandRegistry.SECURE_COPY_STATE_KEY);
        this.clipboardGuard.setSecureCopyMode(secureCopyState === "true");
        const aiModeState = await this.context.secrets.get(CommandRegistry.AI_MODE_STATE_KEY);
        this.aiModeEnabled = aiModeState === "true";
        await vscode.commands.executeCommand("setContext", "devLeakShield.secureCopyEnabled", this.clipboardGuard.isSecureCopyEnabled());
        await vscode.commands.executeCommand("setContext", "devLeakShield.aiModeEnabled", this.aiModeEnabled);
    }
    registerCommands() {
        if (!this.clipboardGuard || !this.firewall || !this.secureVault || !this.workspaceLocker) {
            throw new Error("Services not initialized. Call initializeServices() first.");
        }
        this.secureCopyStatusBarItem = this.statusBarManager.createItem("", "devLeakShield.toggleSecureCopyMode", vscode.StatusBarAlignment.Left, 98, "");
        this.updateSecureCopyStatus();
        this.aiModeStatusBarItem = this.statusBarManager.createItem("", "devLeakShield.toggleAiMode", vscode.StatusBarAlignment.Left, 97, "");
        this.updateAiModeStatus(this.aiModeEnabled);
        this.context.subscriptions.push(vscode.commands.registerCommand("devLeakShield.showSecurityDashboard", async () => {
            const score = this.dashboard.getCurrentScore();
            const vaultSummary = this.secureVault.getSummary();
            const dashboardMessage = `Security score: ${score} | Vault entries: ${vaultSummary.totalEntries} | Avg risk: ${vaultSummary.averageRiskScore.toFixed(2)}`;
            LoggingService_1.LoggingService.log(dashboardMessage);
            NotificationService_1.NotificationService.showInformation(dashboardMessage);
        }));
        this.context.subscriptions.push(vscode.commands.registerCommand("devLeakShield.generateSecurityReport", async () => {
            const findings = await this.collectWorkspaceFindings();
            const summary = SecurityDashboardService_1.SecurityDashboardService.buildSummary(findings);
            this.dashboard.recordSummary(summary);
            const report = this.reportGenerator.generateJson(findings, this.policyEngine.getRules());
            const document = await vscode.workspace.openTextDocument({ content: report, language: "json" });
            await vscode.window.showTextDocument(document, { preview: true });
            LoggingService_1.LoggingService.log(`Security report generated with ${findings.length} finding(s).`);
        }));
        this.context.subscriptions.push(vscode.commands.registerCommand("devLeakShield.secureCopy", async () => {
            await this.clipboardGuard.secureCopy();
        }));
        this.context.subscriptions.push(vscode.commands.registerCommand("devLeakShield.securePaste", async () => {
            await this.clipboardGuard.securePaste();
        }));
        this.context.subscriptions.push(vscode.commands.registerCommand("devLeakShield.encryptSelection", async () => {
            await this.clipboardGuard.encryptSelection();
        }));
        this.context.subscriptions.push(vscode.commands.registerCommand("devLeakShield.decryptSelection", async () => {
            await this.clipboardGuard.decryptSelection();
        }));
        this.context.subscriptions.push(vscode.commands.registerCommand("devLeakShield.toggleSecureCopyMode", async () => {
            const enabled = this.clipboardGuard.toggleSecureCopyMode();
            await this.context.secrets.store(CommandRegistry.SECURE_COPY_STATE_KEY, String(enabled));
            await vscode.commands.executeCommand("setContext", "devLeakShield.secureCopyEnabled", enabled);
            this.updateSecureCopyStatus();
            LoggingService_1.LoggingService.log(`Secure Copy ${enabled ? "enabled" : "disabled"}.`);
            NotificationService_1.NotificationService.showInformation(`Secure Copy ${enabled ? "enabled" : "disabled"}.`);
        }));
        this.context.subscriptions.push(vscode.commands.registerCommand("devLeakShield.toggleAiMode", async () => {
            await this.updateAiModeStatus(!this.aiModeEnabled, true);
        }));
        this.context.subscriptions.push(vscode.commands.registerCommand("devLeakShield.runPreCommitScan", async () => {
            try {
                const workspaceFolder = vscode.window.activeTextEditor
                    ? vscode.workspace.getWorkspaceFolder(vscode.window.activeTextEditor.document.uri)
                    : vscode.workspace.workspaceFolders?.[0];
                if (!workspaceFolder) {
                    NotificationService_1.NotificationService.showError("Open a workspace folder before running the Git scan.");
                    return;
                }
                const gitScanner = new GitSecurityScanner_1.GitSecurityScanner(this.policyEngine, this.secretDetectionService, workspaceFolder.uri.fsPath);
                const result = await gitScanner.scanStagedFiles();
                if (result.blocked) {
                    NotificationService_1.NotificationService.showError(`Pre-commit scan blocked: ${result.reason}`);
                }
                else {
                    LoggingService_1.LoggingService.log(`Pre-commit scan passed. Secrets scanned: ${result.secretsFound}`);
                    NotificationService_1.NotificationService.showInformation(`Pre-commit scan passed. Secrets scanned: ${result.secretsFound}.`);
                }
            }
            catch (error) {
                NotificationService_1.NotificationService.showError(`Pre-commit scan failed: ${error instanceof Error ? error.message : String(error)}`);
            }
        }));
        this.context.subscriptions.push(vscode.commands.registerCommand("devLeakShield.openVault", async () => {
            try {
                if (!this.secureVault) {
                    throw new Error("Vault not initialized");
                }
                const summary = this.secureVault.getSummary();
                const content = JSON.stringify({
                    status: "initialized",
                    ...summary,
                    note: "Secret values are never displayed by the vault viewer.",
                }, null, 2);
                const document = await vscode.workspace.openTextDocument({
                    content,
                    language: "json",
                });
                await vscode.window.showTextDocument(document, { preview: true });
                LoggingService_1.LoggingService.log(`Vault opened with ${summary.totalEntries} entry or entries.`);
            }
            catch (error) {
                NotificationService_1.NotificationService.showError(`Vault error: ${error instanceof Error ? error.message : String(error)}`);
            }
        }));
        this.context.subscriptions.push(vscode.commands.registerCommand("devLeakShield.analyzeClipboardBeforeCopy", async () => {
            try {
                const clipboard = await vscode.env.clipboard.readText();
                const decision = this.firewall.inspect({ source: "clipboard", text: clipboard });
                if (!decision.allowed) {
                    NotificationService_1.NotificationService.showError(`Clipboard blocked: ${decision.reason}`);
                }
                else {
                    LoggingService_1.LoggingService.log(`Clipboard safe: risk=${decision.risk.toFixed(2)}`);
                }
            }
            catch (error) {
                NotificationService_1.NotificationService.showError(`Clipboard analysis failed: ${error instanceof Error ? error.message : String(error)}`);
            }
        }));
    }
    getClipboardGuard() {
        return this.clipboardGuard;
    }
    updateSecureCopyStatus() {
        const enabled = this.clipboardGuard.isSecureCopyEnabled();
        this.secureCopyStatusBarItem.text = enabled
            ? "$(circle-filled) Secure Copy"
            : "$(circle-large-outline) Secure Copy";
        this.secureCopyStatusBarItem.tooltip = enabled
            ? "Secure Copy is ON. Copying replaces detected secrets with vault tokens."
            : "Secure Copy is OFF. Click to enable encrypted copy.";
    }
    async updateAiModeStatus(enabled, fromClick = false) {
        this.aiModeEnabled = enabled;
        this.aiModeStatusBarItem.text = enabled
            ? "$(circle-filled) AI Mode"
            : "$(circle-large-outline) AI Mode";
        this.aiModeStatusBarItem.tooltip = enabled
            ? "AI Mode is ON. Workspace secrets are masked."
            : "AI Mode is OFF. Click to mask workspace secrets.";
        await vscode.commands.executeCommand("setContext", "devLeakShield.aiModeEnabled", enabled);
        if (fromClick) {
            await this.context.secrets.store(CommandRegistry.AI_MODE_STATE_KEY, String(enabled));
            try {
                if (enabled) {
                    await this.workspaceLocker.lockWorkspace();
                    LoggingService_1.LoggingService.log("AI Mode engaged: workspace secrets masked.");
                }
                else {
                    await this.workspaceLocker.unlockWorkspace();
                    LoggingService_1.LoggingService.log("AI Mode disengaged: workspace secrets restored.");
                }
            }
            catch (error) {
                const action = enabled ? 'lock' : 'unlock';
                NotificationService_1.NotificationService.showError(`Failed to ${action} workspace: ${error instanceof Error ? error.message : String(error)}`);
                await this.context.secrets.store(CommandRegistry.AI_MODE_STATE_KEY, String(!enabled));
                await this.updateAiModeStatus(!enabled);
            }
        }
    }
    async collectWorkspaceFindings() {
        const files = await vscode.workspace.findFiles("**/*.{ts,tsx,js,jsx,json,md,env,txt,yml,yaml}", "**/{node_modules,out,dist,build,.git}/**");
        const findings = [];
        for (const file of files) {
            try {
                const document = await vscode.workspace.openTextDocument(file);
                findings.push(...this.secretDetectionService.detect(document.getText(), file.fsPath).findings);
            }
            catch (error) {
                LoggingService_1.LoggingService.log(`Skipped ${file.fsPath}: ${error instanceof Error ? error.message : String(error)}`);
            }
        }
        return findings;
    }
}
exports.CommandRegistry = CommandRegistry;
CommandRegistry.DEFAULT_POLICIES = [
    {
        id: "policy-high-risk",
        name: "High risk secrecy policy",
        description: "Block secrets with a risk score above 0.8.",
        threshold: 0.8,
        categories: ["openai", "aws", "github", "jwt", "ssh", "database", "api_key", "generic"],
        enabled: true,
        allowlist: [],
        denylist: [],
    },
];
CommandRegistry.SECURE_COPY_STATE_KEY = "devLeakShield.secureCopyState";
CommandRegistry.AI_MODE_STATE_KEY = "devLeakShield.aiModeState";
//# sourceMappingURL=CommandRegistry.js.map