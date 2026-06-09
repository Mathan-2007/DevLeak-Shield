"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.GitSecurityService = void 0;
const child_process = require("child_process");
const SecretDetectionService_1 = require("../secrets/SecretDetectionService");
class GitSecurityService {
    constructor(policyEngine) {
        this.policyEngine = policyEngine;
        this.detection = new SecretDetectionService_1.SecretDetectionService();
    }
    scanStagedFiles() {
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
    async validateCommit() {
        const files = await this.scanStagedFiles();
        const violations = [];
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
exports.GitSecurityService = GitSecurityService;
//# sourceMappingURL=GitSecurityService.js.map