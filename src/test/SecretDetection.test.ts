import { expect } from "chai";
import { SecretDetectionService } from "../core/secrets/SecretDetectionService";

describe("SecretDetectionService", () => {
  it("should detect an OpenAI key and assign a risk score", () => {
    const service = new SecretDetectionService();
    const text = "const token = \"sk-1234567890abcdef\";";
    const result = service.detect(text);

    expect(result.findings).to.have.lengthOf.at.least(1);
    expect(result.findings[0].category).to.equal("openai");
    expect(result.maxRisk).to.be.greaterThan(0);
  });
});
