"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const chai_1 = require("chai");
const AiPromptFirewall_1 = require("../core/firewall/AiPromptFirewall");
const PolicyEngine_1 = require("../core/policies/PolicyEngine");
describe("AiPromptFirewall", () => {
    it("should block clipboard content with sensitive secrets when policy triggers", () => {
        const engine = new PolicyEngine_1.PolicyEngine([
            {
                id: "ai-policy",
                name: "AI clipboard block",
                description: "Block high-risk secret transmission.",
                threshold: 0.5,
                categories: ["openai"],
                enabled: true,
                allowlist: [],
                denylist: [],
            },
        ]);
        const firewall = new AiPromptFirewall_1.AiPromptFirewall(engine);
        const decision = firewall.inspect({ source: "clipboard", text: "sk-1234567890abcdef" });
        (0, chai_1.expect)(decision.allowed).to.be.false;
        (0, chai_1.expect)(decision.risk).to.be.greaterThan(0);
    });
});
//# sourceMappingURL=AiPromptFirewall.test.js.map