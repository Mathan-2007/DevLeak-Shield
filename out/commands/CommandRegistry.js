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
        // Initialize policy engine with default policies
        this.policyEngine = new PolicyEngine_1.PolicyEngine([
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
        ]);
    }
    async initializeServices() {
        // Load policies from configuration
        const config = vscode.workspace.getConfiguration("devLeakShield");
        const policies = config.get("policies", [
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
        ]);
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
    }
    registerCommands() {
        if (!this.clipboardGuard || !this.firewall || !this.secureVault || !this.workspaceLocker) {
            throw new Error("Services not initialized. Call initializeServices() first.");
        }
        this.secureCopyStatusBarItem = this.statusBarManager.createItem(this.clipboardGuard.isSecureCopyEnabled() ? "🟢 Secure Copy" : "🔴 Secure Copy", "devLeakShield.toggleSecureCopyMode", vscode.StatusBarAlignment.Left, 98, "Toggle secure copy mode for DevLeakShield.");
        this.aiModeStatusBarItem = this.statusBarManager.createItem("🔴 AI Mode", // Initial state is OFF
        "devLeakShield.toggleAiMode", vscode.StatusBarAlignment.Left, 97, "Toggle AI Mode to mask/unmask secrets in the workspace.");
        this.context.secrets.get(CommandRegistry.AI_MODE_STATE_KEY).then(state => this.updateAiModeStatus(state === 'true'));
        this.context.subscriptions.push(vscode.commands.registerCommand("devLeakShield.showSecurityDashboard", async () => {
            const score = this.dashboard.getCurrentScore();
            const vaultSummary = this.secureVault.getSummary();
            const dashboardMessage = `Security score: ${score} | Vault entries: ${vaultSummary.totalEntries} | Avg risk: ${vaultSummary.averageRiskScore.toFixed(2)}`;
            LoggingService_1.LoggingService.log(dashboardMessage);
        }));
        this.context.subscriptions.push(vscode.commands.registerCommand("devLeakShield.generateSecurityReport", async () => {
            const findings = [];
            const report = this.reportGenerator.generateJson(findings, this.policyEngine.getRules());
            const document = await vscode.workspace.openTextDocument({ content: report, language: "json" });
            await vscode.window.showTextDocument(document, { preview: true });
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
            this.secureCopyStatusBarItem.text = enabled ? "🟢 Secure Copy" : "🔴 Secure Copy";
            LoggingService_1.LoggingService.log(`Secure Copy ${enabled ? "enabled" : "disabled"}.`);
        }));
        this.context.subscriptions.push(vscode.commands.registerCommand("devLeakShield.toggleAiMode", async () => {
            const currentState = this.aiModeStatusBarItem.text.includes("🟢");
            const newState = !currentState;
            this.updateAiModeStatus(newState, true);
        }));
        this.context.subscriptions.push(vscode.commands.registerCommand("devLeakShield.runPreCommitScan", async () => {
            try {
                const gitScanner = new GitSecurityScanner_1.GitSecurityScanner(this.policyEngine, this.secretDetectionService);
                const result = await gitScanner.scanStagedFiles();
                if (result.blocked) {
                    NotificationService_1.NotificationService.showError(`Pre-commit scan blocked: ${result.reason}`);
                }
                else {
                    LoggingService_1.LoggingService.log(`Pre-commit scan passed. Secrets scanned: ${result.secretsFound}`);
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
                const message = `Vault initialized | Entries: ${summary.totalEntries} | Categories: ${JSON.stringify(summary.entriesByCategory)}`;
                LoggingService_1.LoggingService.log(message);
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
    async updateAiModeStatus(enabled, fromClick = false) {
        this.aiModeStatusBarItem.text = enabled ? "🟢 AI Mode" : "🔴 AI Mode";
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
                // Revert UI on failure
                this.aiModeStatusBarItem.text = !enabled ? "🟢 AI Mode" : "🔴 AI Mode";
                await this.context.secrets.store(CommandRegistry.AI_MODE_STATE_KEY, String(!enabled));
            }
        }
    }
}
exports.CommandRegistry = CommandRegistry;
CommandRegistry.SECURE_COPY_STATE_KEY = "devLeakShield.secureCopyState";
CommandRegistry.AI_MODE_STATE_KEY = "devLeakShield.aiModeState";
//# sourceMappingURL=CommandRegistry.js.map