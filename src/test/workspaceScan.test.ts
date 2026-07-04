/**
 * workspaceScan.test.ts
 *
 * ASSUMPTIONS:
 * - scanWorkspaceForSecrets(rootPath: string, detector, maxFiles = 50): Finding[]
 * - Per your own analysis, this currently hard-caps at 50 files. These tests
 *   confirm that documented limit explicitly, so nobody "fixes" it silently
 *   without also updating the README/report UI to disclose partial scans.
 *
 * Uses a temp directory with generated fixture files rather than mocking fs,
 * so the test exercises real file I/O the same way the extension will.
 */

import { expect } from "chai";
import * as fs from "fs";
import * as os from "os";
import * as path from "path";
import { SecretDetectionService } from "./SecretDetectionService";
import { scanWorkspaceForSecrets } from "./workspaceScan";

function makeTempWorkspace(fileCount: number, withSecretInEvery: boolean): string {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "dls-test-"));
  for (let i = 0; i < fileCount; i++) {
    const content = withSecretInEvery
      ? `OPENAI_API_KEY=sk-live-fake${i}fake${i}fake${i}fake\n`
      : `const value${i} = ${i};\n`;
    fs.writeFileSync(path.join(dir, `file${i}.env`), content);
  }
  return dir;
}

describe("Workspace scan", () => {
  let detector: SecretDetectionService;

  beforeEach(() => {
    detector = new SecretDetectionService();
  });

  it("finds secrets across multiple files under the file cap", () => {
    const dir = makeTempWorkspace(10, true);
    const findings = scanWorkspaceForSecrets(dir, detector);
    expect(findings.length).to.equal(10);
    fs.rmSync(dir, { recursive: true, force: true });
  });

  it("respects the documented 50-file cap and does not scan beyond it", () => {
    const dir = makeTempWorkspace(75, true);
    const findings = scanWorkspaceForSecrets(dir, detector);

    // Cap means we should see at most 50 files' worth of findings (1 per file here)
    expect(findings.length).to.be.at.most(50);
    fs.rmSync(dir, { recursive: true, force: true });
  });

  it("returns an empty array for a workspace with no secrets", () => {
    const dir = makeTempWorkspace(5, false);
    const findings = scanWorkspaceForSecrets(dir, detector);
    expect(findings).to.deep.equal([]);
    fs.rmSync(dir, { recursive: true, force: true });
  });

  it("does not throw on an empty workspace directory", () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "dls-empty-"));
    expect(() => scanWorkspaceForSecrets(dir, detector)).to.not.throw();
    fs.rmSync(dir, { recursive: true, force: true });
  });

  it("does not throw when a workspace path does not exist", () => {
    expect(() => scanWorkspaceForSecrets("/path/does/not/exist", detector)).to.not.throw();
  });

  it("each finding includes enough metadata to locate it (file path + line)", () => {
    const dir = makeTempWorkspace(1, true);
    const findings = scanWorkspaceForSecrets(dir, detector);
    expect(findings[0]).to.have.property("filePath");
    expect(findings[0]).to.have.property("line");
    fs.rmSync(dir, { recursive: true, force: true });
  });
});
