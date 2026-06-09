import { FirewallContext, PolicyDecision } from "../../types";
import { SecretDetectionService } from "../secrets/SecretDetectionService";
import { PolicyEngine } from "../policies/PolicyEngine";

export class AiPromptFirewall {
  private readonly detection = new SecretDetectionService();

  constructor(private readonly policyEngine: PolicyEngine) {}

  inspect(context: FirewallContext): PolicyDecision {
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
