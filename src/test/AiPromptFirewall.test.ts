import { expect } from "chai";
import { AiPromptFirewall } from "../core/firewall/AiPromptFirewall";
import { PolicyEngine } from "../core/policies/PolicyEngine";

describe("AiPromptFirewall", () => {
  it("should block clipboard content with sensitive secrets when policy triggers", () => {
    const engine = new PolicyEngine([
      {
        id: "ai-policy",
        name: "AI clipboard block",
        description: "Block high-risk secret transmission.",
        threshold: 0.0, // Block all detected secrets
        categories: ["openai"],
        enabled: true,
        allowlist: [],
        denylist: [],
      },
    ]);

    const firewall = new AiPromptFirewall(engine);
    const decision = firewall.inspect({ source: "clipboard", text: "const apiKey = 'sk-1234567890abcdefghij';" });

    expect(decision.allowed).to.be.false;
    expect(decision.risk).to.be.greaterThan(0);
  });
});
