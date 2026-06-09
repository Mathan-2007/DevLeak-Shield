import { AiPromptFirewall } from "../core/firewall/AiPromptFirewall";
import { SecretClassifier } from "../core/secrets/SecretClassifier";
import { SecretDetectionService } from "../core/secrets/SecretDetectionService";
import { PolicyEngine } from "../core/policies/PolicyEngine";
import { SecureVault } from "../core/vault/SecureVault";
import { ClipboardAuditService } from "./ClipboardAuditService";
import { SecretCategory } from "../types";

export interface SecureCopyResult {
  text: string;
  blocked: boolean;
  reason?: string;
  risk: number;
  secretsProtected: number;
}

/**
 * SecureCopyService: Zero-trust secure copy with vault-backed tokens
 *
 * Workflow:
 * 1. Detect secrets in selected text
 * 2. Classify by category (openai, aws, github, etc.)
 * 3. Evaluate against policy and firewall
 * 4. If allowed: Store secret in vault, replace with token
 * 5. If blocked: Log audit record, return original text
 *
 * Token design:
 * - Contains ONLY vault reference ID
 * - Never contains secret or encryption key
 * - Token theft cannot recover secret
 * - Token = DEVLEAKSHIELD_TOKEN_<uuid>
 */
export class SecureCopyService {
  private readonly detection = new SecretDetectionService();
  private readonly classifier = new SecretClassifier();

  constructor(
    private readonly policyEngine: PolicyEngine,
    private readonly firewall: AiPromptFirewall,
    private readonly auditService: ClipboardAuditService,
    private readonly vault: SecureVault
  ) {}

  async copy(text: string): Promise<SecureCopyResult> {
    const detectionResult = this.detection.detect(text);
    const secretTypes = Array.from(new Set(detectionResult.findings.map((finding) => finding.category)));
    const riskScore = detectionResult.maxRisk;

    // Check policy
    const policyDecision = this.policyEngine.evaluate(detectionResult.findings);
    
    // Check firewall
    const firewallDecision = this.firewall.inspect({ source: "clipboard", text });
    
    const blocked = !policyDecision.allowed || !firewallDecision.allowed;

    if (blocked) {
      const reason = [policyDecision.reason, firewallDecision.reason].filter(Boolean).join(" ");
      this.auditService.log({
        action: "blocked_copy",
        timestamp: new Date().toISOString(),
        riskScore,
        secretTypes,
        success: false,
        reason,
        itemCount: detectionResult.findings.length,
      });
      return { text, blocked: true, reason, risk: riskScore, secretsProtected: 0 };
    }

    // Store secrets in vault, replace with tokens
    let output = text;
    let secretsProtected = 0;

    for (const finding of detectionResult.findings) {
      try {
        const classification = this.classifier.classify(finding.value) as SecretCategory;
        const vaultResult = await this.vault.store(finding.value, classification, riskScore, {
          source: "clipboard_copy",
          filePath: "clipboard",
        });

        // Replace secret with token
        output = output.replaceAll(finding.value, vaultResult.token);
        secretsProtected += 1;

        if (!secretTypes.includes(classification)) {
          secretTypes.push(classification);
        }
      } catch (error) {
        const reason = `Failed to store secret in vault: ${error instanceof Error ? error.message : String(error)}`;
        this.auditService.log({
          action: "blocked_copy",
          timestamp: new Date().toISOString(),
          riskScore,
          secretTypes,
          success: false,
          reason,
          itemCount: 1,
        });
        return { text, blocked: true, reason, risk: riskScore, secretsProtected: 0 };
      }
    }

    // Log successful copy
    this.auditService.log({
      action: "secure_copy",
      timestamp: new Date().toISOString(),
      riskScore,
      secretTypes,
      success: true,
      itemCount: secretsProtected,
    });

    return { text: output, blocked: false, risk: riskScore, secretsProtected };
  }
}
