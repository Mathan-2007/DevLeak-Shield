/// <reference types="mocha" />

import { expect } from "chai";
import { SecretDetectionService } from "../core/secrets/SecretDetectionService";
import { SecretClassifier } from "../core/secrets/SecretClassifier";

describe("SecretDetectionService custom patterns", () => {
  it("detects secrets that match configured custom regex patterns", () => {
    const service = new SecretDetectionService([
      {
        name: "internal_api_key",
        pattern: "INTERNAL_[A-Z0-9]{20}",
        category: "api_key",
      },
    ]);

    const result = service.detect("The deployment token is INTERNAL_ABC123DEF456GHI789JKL");

    expect(result.findings).to.have.lengthOf(1);
    expect(result.findings[0].category).to.equal("api_key");
    expect(result.findings[0].value).to.contain("INTERNAL_");
  });

  it("keeps ordinary paths from being treated as high-confidence custom secrets", () => {
    const classifier = new SecretClassifier();
    const confidence = classifier.getConfidence("/page/page2", "custom");

    expect(confidence).to.equal(0.2);
  });
});
