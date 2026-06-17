import * as vscode from "vscode";
import { AiPromptFirewall } from "../core/firewall/AiPromptFirewall";
import { PolicyEngine } from "../core/policies/PolicyEngine";
import { ReportGenerator } from "../core/reports/ReportGenerator";
import { SecurityDashboardService } from "../core/dashboard/SecurityDashboardService";
import { SecureVault } from "../core/vault/SecureVault";
import { WorkspaceLocker } from "../platform/WorkspaceLocker";
import { SecretDetectionService } from "../core/secrets/SecretDetectionService";
import { SessionManager } from "../core/session/SessionManager";
import { StatusBarManager } from "../ui/StatusBarManager";
import { ClipboardGuard } from "../clipboard/ClipboardGuard";
import { GitSecurityScanner } from "../core/git/GitSecurityScanner";
import { PolicyRule, SecretFinding } from "../types";
import { NotificationService } from "../ui/NotificationService";
import { LoggingService } from "../ui/LoggingService";

export class CommandRegistry {
  private static readonly DEFAULT_POLICIES: PolicyRule[] = [
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

  private readonly reportGenerator = new ReportGenerator();
  private readonly secretDetectionService = new SecretDetectionService();
  private policyEngine: PolicyEngine;
  private clipboardGuard!: ClipboardGuard;
  private secureVault?: SecureVault;
  private workspaceLocker!: WorkspaceLocker;
  private firewall!: AiPromptFirewall;

  private secureCopyStatusBarItem!: vscode.StatusBarItem;
  private aiModeStatusBarItem!: vscode.StatusBarItem;
  private aiModeEnabled = false;

  private static readonly SECURE_COPY_STATE_KEY = "devLeakShield.secureCopyState";
  private static readonly AI_MODE_STATE_KEY = "devLeakShield.aiModeState";

  constructor(
    private readonly context: vscode.ExtensionContext,
    private readonly sessionManager: SessionManager,
    private readonly statusBarManager: StatusBarManager
  ) {
    // Initialize policy engine with default policies
    this.policyEngine = new PolicyEngine(CommandRegistry.DEFAULT_POLICIES);
  }

  async initializeServices(): Promise<void> {
    // Load policies from configuration
    const config = vscode.workspace.getConfiguration("devLeakShield");
    const configuredPolicies = config.get<PolicyRule[]>("policies");
    const policies = configuredPolicies && configuredPolicies.length > 0
      ? configuredPolicies
      : CommandRegistry.DEFAULT_POLICIES;

    this.policyEngine = new PolicyEngine(policies);
    this.firewall = new AiPromptFirewall(this.policyEngine);
    const masterKey = this.sessionManager.getMasterKey();

    // Initialize vault and clipboard guard
    this.secureVault = new SecureVault(this.context.secrets, masterKey);
    await this.secureVault.initialize();

    this.clipboardGuard = new ClipboardGuard(
      this.policyEngine,
      this.firewall,
      this.secureVault
    );

    this.workspaceLocker = new WorkspaceLocker(
      this.context.secrets,
      this.secureVault,
      this.secretDetectionService
    );

    // Restore persisted states
    const secureCopyState = await this.context.secrets.get(CommandRegistry.SECURE_COPY_STATE_KEY);
    this.clipboardGuard.setSecureCopyMode(secureCopyState === "true");
    const aiModeState = await this.context.secrets.get(CommandRegistry.AI_MODE_STATE_KEY);
    this.aiModeEnabled = aiModeState === "true";
    await vscode.commands.executeCommand(
      "setContext",
      "devLeakShield.secureCopyEnabled",
      this.clipboardGuard.isSecureCopyEnabled()
    );
    await vscode.commands.executeCommand(
      "setContext",
      "devLeakShield.aiModeEnabled",
      this.aiModeEnabled
    );
  }

  registerCommands(): void {
    if (!this.clipboardGuard || !this.firewall || !this.secureVault || !this.workspaceLocker) {
      throw new Error("Services not initialized. Call initializeServices() first.");
    }

    this.secureCopyStatusBarItem = this.statusBarManager.createItem(
      "",
      "devLeakShield.toggleSecureCopyMode",
      vscode.StatusBarAlignment.Left,
      98,
      ""
    );
    this.updateSecureCopyStatus();

    this.aiModeStatusBarItem = this.statusBarManager.createItem(
      "",
      "devLeakShield.toggleAiMode",
      vscode.StatusBarAlignment.Left,
      97,
      ""
    );
    this.updateAiModeStatus(this.aiModeEnabled);

    this.context.subscriptions.push(
      vscode.commands.registerCommand("devLeakShield.generateSecurityReport", async () => {
        const findings = await this.collectWorkspaceFindings();
        const report = this.reportGenerator.generateJson(findings, this.policyEngine.getRules());
        const document = await vscode.workspace.openTextDocument({ content: report, language: "json" });
        await vscode.window.showTextDocument(document, { preview: true });
        LoggingService.log(`Security report generated with ${findings.length} finding(s).`);
      })
    );

    this.context.subscriptions.push(
      vscode.commands.registerCommand("devLeakShield.toggleSecureCopyMode", async () => {
        const enabled = this.clipboardGuard!.toggleSecureCopyMode();
        await this.context.secrets.store(CommandRegistry.SECURE_COPY_STATE_KEY, String(enabled));
        await vscode.commands.executeCommand("setContext", "devLeakShield.secureCopyEnabled", enabled);
        this.updateSecureCopyStatus();
        LoggingService.log(`Secure Copy ${enabled ? "enabled" : "disabled"}.`);
        NotificationService.showInformation(`Secure Copy ${enabled ? "enabled" : "disabled"}.`);
      })
    );

    this.context.subscriptions.push(
      vscode.commands.registerCommand("devLeakShield.toggleAiMode", async () => {
        await this.updateAiModeStatus(!this.aiModeEnabled, true);
      })
    );

    this.context.subscriptions.push(
      vscode.commands.registerCommand("devLeakShield.analyzeClipboardBeforeCopy", async () => {
        try {
          const clipboard = await vscode.env.clipboard.readText();
          const decision = this.firewall!.inspect({ source: "clipboard", text: clipboard });
          if (!decision.allowed) {
            NotificationService.showError(`Clipboard blocked: ${decision.reason}`);
          } else {
            LoggingService.log(`Clipboard safe: risk=${decision.risk.toFixed(2)}`);
          }
        } catch (error) {
          NotificationService.showError(`Clipboard analysis failed: ${error instanceof Error ? error.message : String(error)}`);
        }
      })
    );
  }

  getClipboardGuard(): ClipboardGuard {
    return this.clipboardGuard;
  }

  private updateSecureCopyStatus(): void {
    const enabled = this.clipboardGuard.isSecureCopyEnabled();
    this.secureCopyStatusBarItem.text = enabled
      ? "$(circle-filled) Secure Copy"
      : "$(circle-large-outline) Secure Copy";
    this.secureCopyStatusBarItem.tooltip = enabled
      ? "Secure Copy is ON. Copying replaces detected secrets with vault tokens."
      : "Secure Copy is OFF. Click to enable encrypted copy.";
  }

  private async updateAiModeStatus(enabled: boolean, fromClick = false): Promise<void> {
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
          LoggingService.log("AI Mode engaged: workspace secrets masked.");
        } else {
          await this.workspaceLocker.unlockWorkspace();
          LoggingService.log("AI Mode disengaged: workspace secrets restored.");
        }
      } catch (error) {
        const action = enabled ? 'lock' : 'unlock';
        NotificationService.showError(`Failed to ${action} workspace: ${error instanceof Error ? error.message : String(error)}`);
        await this.context.secrets.store(CommandRegistry.AI_MODE_STATE_KEY, String(!enabled));
        await this.updateAiModeStatus(!enabled);
      }
    }
  }

  private async collectWorkspaceFindings(): Promise<SecretFinding[]> {
    const files = await vscode.workspace.findFiles(
      "**/*.{ts,tsx,js,jsx,json,md,env,txt,yml,yaml}",
      "**/{node_modules,out,dist,build,.git}/**"
    );
    const findings: SecretFinding[] = [];

    for (const file of files) {
      try {
        const document = await vscode.workspace.openTextDocument(file);
        findings.push(...this.secretDetectionService.detect(document.getText(), file.fsPath).findings);
      } catch (error) {
        LoggingService.log(
          `Skipped ${file.fsPath}: ${error instanceof Error ? error.message : String(error)}`
        );
      }
    }
    // IMPROVEMENT: Use Promise.all for parallel processing. For a true performance gain,
    // this should be moved to a worker thread to avoid blocking the main extension host process.
    await Promise.all(files.map(async (file) => {
        try {
            const document = await vscode.workspace.openTextDocument(file);
            findings.push(...this.secretDetectionService.detect(document.getText(), file.fsPath).findings);
        } catch (error) {
            LoggingService.log(
                `Skipped ${file.fsPath}: ${error instanceof Error ? error.message : String(error)}`
            );
        }
    }));

    return findings;
  }
}
