"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const chai_1 = require("chai");
const SecretDetectionService_1 = require("../core/secrets/SecretDetectionService");
describe("SecretDetectionService", () => {
    it("should detect an OpenAI key and assign a risk score", () => {
        const service = new SecretDetectionService_1.SecretDetectionService();
        const text = "const token = \"sk-1234567890abcdef\";";
        const result = service.detect(text);
        (0, chai_1.expect)(result.findings).to.have.lengthOf.at.least(1);
        (0, chai_1.expect)(result.findings[0].category).to.equal("openai");
        (0, chai_1.expect)(result.maxRisk).to.be.greaterThan(0);
    });
});
//# sourceMappingURL=SecretDetection.test.js.map