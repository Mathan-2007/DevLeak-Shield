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
    }
    registerCommands() {
        if (!this.clipboardGuard || !this.firewall || !this.secureVault || !this.workspaceLocker) {
            throw new Error("Services not initialized. Call initializeServices() first.");
        }
        this.secureCopyStatusBarItem = this.statusBarManager.createItem("DevLeakShield Secure Copy OFF", "devLeakShield.toggleSecureCopyMode", vscode.StatusBarAlignment.Left, 98, "Toggle secure copy mode for DevLeakShield.");
        this.context.subscriptions.push(vscode.commands.registerCommand("devLeakShield.showSecurityDashboard", async () => {
            const score = this.dashboard.getCurrentScore();
            const vaultSummary = this.secureVault.getSummary();
            const dashboardMessage = `Security score: ${score} | Vault entries: ${vaultSummary.totalEntries} | Avg risk: ${vaultSummary.averageRiskScore.toFixed(2)}`;
            vscode.window.showInformationMessage(dashboardMessage);
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
            if (this.secureCopyStatusBarItem) {
                this.secureCopyStatusBarItem.text = enabled
                    ? "DevLeakShield Secure Copy ON"
                    : "DevLeakShield Secure Copy OFF";
            }
            vscode.window.showInformationMessage(`DevLeakShield secure copy ${enabled ? "enabled" : "disabled"}.`);
        }));
        this.context.subscriptions.push(vscode.commands.registerCommand("devLeakShield.toggleAiMode", async () => {
            try {
                await this.workspaceLocker.lockWorkspace();
                vscode.window.showInformationMessage("AI Mode engaged: workspace secrets masked and stored in vault.");
            }
            catch (error) {
                vscode.window.showErrorMessage(`Failed to lock workspace: ${error instanceof Error ? error.message : String(error)}`);
            }
        }));
        this.context.subscriptions.push(vscode.commands.registerCommand("devLeakShield.runPreCommitScan", async () => {
            try {
                const gitScanner = new GitSecurityScanner_1.GitSecurityScanner(this.policyEngine, this.secretDetectionService);
                const result = await gitScanner.scanStagedFiles();
                if (result.blocked) {
                    vscode.window.showErrorMessage(`Pre-commit scan blocked: ${result.reason}`);
                }
                else {
                    vscode.window.showInformationMessage(`Pre-commit scan passed. Secrets scanned: ${result.secretsFound}`);
                }
            }
            catch (error) {
                vscode.window.showErrorMessage(`Pre-commit scan failed: ${error instanceof Error ? error.message : String(error)}`);
            }
        }));
        this.context.subscriptions.push(vscode.commands.registerCommand("devLeakShield.openVault", async () => {
            try {
                if (!this.secureVault) {
                    throw new Error("Vault not initialized");
                }
                const summary = this.secureVault.getSummary();
                const message = `Vault initialized | Entries: ${summary.totalEntries} | Categories: ${JSON.stringify(summary.entriesByCategory)}`;
                vscode.window.showInformationMessage(message);
            }
            catch (error) {
                vscode.window.showErrorMessage(`Vault error: ${error instanceof Error ? error.message : String(error)}`);
            }
        }));
        this.context.subscriptions.push(vscode.commands.registerCommand("devLeakShield.analyzeClipboardBeforeCopy", async () => {
            try {
                const clipboard = await vscode.env.clipboard.readText();
                const decision = this.firewall.inspect({ source: "clipboard", text: clipboard });
                if (!decision.allowed) {
                    vscode.window.showErrorMessage(`Clipboard blocked: ${decision.reason}`);
                }
                else {
                    vscode.window.showInformationMessage(`Clipboard safe: risk=${decision.risk.toFixed(2)}`);
                }
            }
            catch (error) {
                vscode.window.showErrorMessage(`Clipboard analysis failed: ${error instanceof Error ? error.message : String(error)}`);
            }
        }));
    }
}
exports.CommandRegistry = CommandRegistry;
//# sourceMappingURL=CommandRegistry.js.map