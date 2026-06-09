import { expect } from "chai";
import { PolicyEngine } from "../core/policies/PolicyEngine";

const findings = [
  {
    value: "sk-1234567890abcdef",
    category: "openai",
    location: {},
    detection: {
      regexMatch: true,
      entropyScore: 0.9,
      contextScore: 0.8,
      confidence: 0.95,
      risk: 0.9,
      features: ["regex", "entropy"],
    },
  },
];

describe("PolicyEngine", () => {
  it("should block high-risk findings when threshold is exceeded", () => {
    const engine = new PolicyEngine([
      {
        id: "test-policy",
        name: "Block high risk",
        description: "Block risk above 0.8",
        threshold: 0.8,
        categories: ["openai"],
        enabled: true,
        allowlist: [],
        denylist: [],
      },
    ]);

    const decision = engine.evaluate(findings as any);
    expect(decision.allowed).to.be.false;
    expect(decision.reason).to.contain("Policy violation");
  });
});
