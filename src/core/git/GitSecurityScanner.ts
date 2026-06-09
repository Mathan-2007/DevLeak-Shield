import { execFile } from "child_process";
import { promisify } from "util";
import { SecretDetectionService } from "../secrets/SecretDetectionService";
import { PolicyEngine } from "../policies/PolicyEngine";

const execFileAsync = promisify(execFile);

/**
 * GitSecurityScanner: Cross-platform staged file secret scanning
 *
 * Design:
 * - Scan git staged files for secrets before commit
 * - Use execFile (not execSync) for non-blocking I/O
 * - Support Windows, Linux, macOS
 * - Prevent secret commits
 * - Report findings with policy evaluation
 *
 * Workflow:
 * 1. Get staged files via `git diff --cached --name-only`
 * 2. Get content of each staged file via `git show :path`
 * 3. Detect secrets in staged content
 * 4. Evaluate against policy
 * 5. Block if secrets found above threshold
 */
export class GitSecurityScanner {
  constructor(
    private readonly policyEngine: PolicyEngine,
    private readonly secretDetectionService: SecretDetectionService,
    private readonly cwd?: string
  ) {}

  /**
   * Scan staged files for secrets
   */
  async scanStagedFiles(): Promise<{
    blocked: boolean;
    reason: string;
    secretsFound: number;
  }> {
    try {
      // Get list of staged files
      const { stdout: stagedFiles } = await execFileAsync("git", ["diff", "--cached", "--name-only"], {
        encoding: "utf8",
        cwd: this.cwd,
      });

      if (!stagedFiles.trim()) {
        return { blocked: false, reason: "No staged files", secretsFound: 0 };
      }

      const files = stagedFiles.trim().split("\n");
      let totalSecretsFound = 0;
      const blockedFiles: string[] = [];

      for (const file of files) {
        if (!file.trim()) continue;

        try {
          // Get content of staged file
          const { stdout: content } = await execFileAsync("git", ["show", `:${file}`], {
            encoding: "utf8",
            maxBuffer: 10 * 1024 * 1024, // 10MB buffer
            cwd: this.cwd,
          });

          // Detect secrets
          const result = this.secretDetectionService.detect(content, file);

          if (result.findings.length > 0) {
            totalSecretsFound += result.findings.length;

            // Evaluate against policy
            const decision = this.policyEngine.evaluate(result.findings);

            if (!decision.allowed) {
              blockedFiles.push(`${file}: ${decision.reason}`);
            }
          }
        } catch (error) {
          // Skip files that can't be read (e.g., deleted files)
          if (!(error instanceof Error) || !error.message.includes("pathspec did not match")) {
            console.error(`Error scanning file ${file}:`, error);
          }
        }
      }

      if (blockedFiles.length > 0) {
        return {
          blocked: true,
          reason: `Pre-commit scan blocked. Files with secrets: ${blockedFiles.join("; ")}`,
          secretsFound: totalSecretsFound,
        };
      }

      return {
        blocked: false,
        reason: `Pre-commit scan passed. ${totalSecretsFound} secrets detected but allowed by policy.`,
        secretsFound: totalSecretsFound,
      };
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);

      // Not a git repo or git not available
      if (message.includes("not a git repository") || message.includes("git: command not found")) {
        return {
          blocked: false,
          reason: "Git not available or not a git repository",
          secretsFound: 0,
        };
      }

      return {
        blocked: true,
        reason: `Pre-commit scan failed: ${message}`,
        secretsFound: 0,
      };
    }
  }
}
