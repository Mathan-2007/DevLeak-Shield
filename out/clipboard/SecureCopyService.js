"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.SecureCopyService = void 0;
const SecretClassifier_1 = require("../core/secrets/SecretClassifier");
const SecretDetectionService_1 = require("../core/secrets/SecretDetectionService");
class SecureCopyService {
    constructor(policyEngine, firewall, auditService, vault) {
        this.policyEngine = policyEngine;
        this.firewall = firewall;
        this.auditService = auditService;
        this.vault = vault;
        this.detection = new SecretDetectionService_1.SecretDetectionService();
        this.classifier = new SecretClassifier_1.SecretClassifier();
    }
    async copy(text) {
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
                const classification = this.classifier.classify(finding.value);
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
            }
            catch (error) {
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
exports.SecureCopyService = SecureCopyService;
//# sourceMappingURL=SecureCopyService.js.map