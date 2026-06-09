import * as child_process from "child_process";
import { PolicyEngine } from "../policies/PolicyEngine";
import { SecretDetectionService } from "../secrets/SecretDetectionService";

export class GitSecurityService {
  private readonly detection = new SecretDetectionService();

  constructor(private readonly policyEngine: PolicyEngine) {}

  scanStagedFiles(): Promise<string[]> {
    return new Promise((resolve, reject) => {
      child_process.exec("git diff --cached --name-only --diff-filter=ACM", (error, stdout) => {
        if (error) {
          return reject(error);
        }
        resolve(stdout
          .trim()
          .split("\n")
          .filter(Boolean));
      });
    });
  }

  async validateCommit(): Promise<void> {
    const files = await this.scanStagedFiles();
    const violations: string[] = [];

    for (const file of files) {
      const content = child_process.execSync(`git show :${file}`, { encoding: "utf8" });
      const result = this.detection.detect(content, file);
      const decision = this.policyEngine.evaluate(result.findings);
      if (!decision.allowed) {
        violations.push(`${file}: ${decision.reason}`);
      }
    }

    if (violations.length > 0) {
      throw new Error(`Commit blocked by DevLeakShield:\n${violations.join("\n")}`);
    }
  }
}
