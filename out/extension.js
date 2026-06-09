"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.activate = activate;
exports.deactivate = deactivate;
const vscode = require("vscode");
const SessionManager_1 = require("./core/session/SessionManager");
const CommandRegistry_1 = require("./commands/CommandRegistry");
const StatusBarManager_1 = require("./ui/StatusBarManager");
const AiPromptFirewall_1 = require("./core/firewall/AiPromptFirewall");
const PolicyEngine_1 = require("./core/policies/PolicyEngine");
let statusBarManager;
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
        // Create default security policies
        const policyEngine = new PolicyEngine_1.PolicyEngine([
            {
                id: "policy-enterprise-threshold",
                name: "Enterprise AI firewall threshold",
                description: "Block secret transmissions based on configured risk thresholds.",
                threshold: 0.7,
                categories: ["openai", "aws", "github", "jwt", "ssh", "database", "api_key", "generic"],
                enabled: true,
                allowlist: [],
                denylist: [],
            },
        ]);
        // Initialize command registry
        const commandRegistry = new CommandRegistry_1.CommandRegistry(context, sessionManager, statusBarManager);
        await commandRegistry.initializeServices();
        commandRegistry.registerCommands();
        console.log("DevLeakShield: Commands registered");
        // Set up status bar
        statusBarManager.createItem("DevLeakShield: Secure", "devLeakShield.showSecurityDashboard", vscode.StatusBarAlignment.Left, 100, "Open DevLeakShield security dashboard.");
        statusBarManager.createItem("DevLeakShield: AI Firewall", "devLeakShield.toggleAiMode", vscode.StatusBarAlignment.Left, 99, "Toggle AI prompt firewall and workspace protection.");
        // Set up AI firewall for clipboard analysis
        const firewall = new AiPromptFirewall_1.AiPromptFirewall(policyEngine);
        context.subscriptions.push(vscode.commands.registerCommand("devLeakShield.analyzeClipboardBeforeCopy", async () => {
            try {
                const clipboard = await vscode.env.clipboard.readText();
                const decision = firewall.inspect({ source: "clipboard", text: clipboard });
                if (!decision.allowed) {
                    vscode.window.showErrorMessage(`Clipboard blocked: ${decision.reason}`);
                    return;
                }
                vscode.window.showInformationMessage(`Clipboard safe: risk=${decision.risk.toFixed(2)}`);
            }
            catch (error) {
                vscode.window.showErrorMessage(`Clipboard analysis failed: ${error instanceof Error ? error.message : String(error)}`);
            }
        }));
        console.log("✅ DevLeakShield activated as enterprise-grade extension with zero-trust vault architecture.");
    }
    catch (error) {
        const message = error instanceof Error ? error.message : String(error);
        console.error(`❌ DevLeakShield activation failed: ${message}`);
        vscode.window.showErrorMessage(`DevLeakShield initialization failed: ${message}`);
    }
}
function deactivate() {
    statusBarManager?.dispose();
    console.log("DevLeakShield deactivated.");
}
//# sourceMappingURL=extension.js.map