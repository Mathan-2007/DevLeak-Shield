"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.AiPromptFirewall = void 0;
const SecretDetectionService_1 = require("../secrets/SecretDetectionService");
class AiPromptFirewall {
    constructor(policyEngine) {
        this.policyEngine = policyEngine;
        this.detection = new SecretDetectionService_1.SecretDetectionService();
    }
    inspect(context) {
        const { text, source } = context;
        if (source !== "clipboard" && source !== "ai") {
            return {
                allowed: true,
                reason: "Firewall only evaluates AI and clipboard traffic.",
                risk: 0,
            };
        }
        const result = this.detection.detect(text);
        if (result.findings.length === 0) {
            return {
                allowed: true,
                reason: "No risky secrets detected before transmission.",
                risk: 0,
            };
        }
        const decision = this.policyEngine.evaluate(result.findings);
        if (!decision.allowed) {
            decision.reason = `AI Prompt Firewall blocked transmission due to ${decision.reason}`;
        }
        return decision;
    }
}
exports.AiPromptFirewall = AiPromptFirewall;
//# sourceMappingURL=AiPromptFirewall.js.map