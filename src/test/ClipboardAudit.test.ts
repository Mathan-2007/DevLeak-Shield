import { expect } from "chai";
import { AiPromptFirewall } from "../core/firewall/AiPromptFirewall";
import { PolicyEngine } from "../core/policies/PolicyEngine";
import { ClipboardAuditService } from "../clipboard/ClipboardAuditService";
import { SecureCopyService } from "../clipboard/SecureCopyService";
import { SecurePasteService } from "../clipboard/SecurePasteService";
import { SecureVault } from "../core/vault/SecureVault";
import { SessionManager } from "../core/session/SessionManager";

// Mock VS Code SecretStorage
class MockSecretStorage {
  private storage: Map<string, string> = new Map();

  async get(key: string): Promise<string | undefined> {
    return this.storage.get(key);
  }

  async store(key: string, value: string): Promise<void> {
    this.storage.set(key, value);
  }

  async delete(key: string): Promise<void> {
    this.storage.delete(key);
  }
}

describe("Clipboard Audit and Vault Integration", () => {
  it("should encrypt detected secrets on secure copy and log the event", async () => {
    const storage = new MockSecretStorage();
    const sessionManager = new SessionManager(storage as any);
    await sessionManager.initialize();
    const masterKey = sessionManager.getMasterKey();

    const vault = new SecureVault(storage as any, masterKey);
    await vault.initialize();

    const policyEngine = new PolicyEngine([
      {
        id: "allow-all",
        name: "Allow all copy",
        description: "Allow all secret copy operations.",
        threshold: 1,
        categories: ["openai", "aws", "github", "jwt", "ssh", "database", "api_key", "generic"],
        enabled: true,
        allowlist: [],
        denylist: [],
      },
    ]);
    const auditService = new ClipboardAuditService();
    const firewall = new AiPromptFirewall(policyEngine);
    const copyService = new SecureCopyService(policyEngine, firewall, auditService, vault);
    const text = "const apiKey = \"sk-1234567890abcd\";";

    const result = await copyService.copy(text);

    expect(result.blocked).to.be.false;
    expect(result.text).to.include("DEVLEAKSHIELD_TOKEN_");
    expect(result.risk).to.be.greaterThan(0);

    const summary = auditService.getSummary();
    expect(summary.totalEvents).to.equal(1);
    expect(summary.encryptedSecretsCount).to.equal(1);
  });

  it("should block secure copy when policy threshold is exceeded", async () => {
    const storage = new MockSecretStorage();
    const sessionManager = new SessionManager(storage as any);
    await sessionManager.initialize();
    const masterKey = sessionManager.getMasterKey();

    const vault = new SecureVault(storage as any, masterKey);
    await vault.initialize();

    const policyEngine = new PolicyEngine([
      {
        id: "block-all",
        name: "Block all secret copy",
        description: "Block if any secret is detected.",
        threshold: 0.0,
        categories: ["openai", "aws", "github", "jwt", "ssh", "database", "api_key", "generic"],
        enabled: true,
        allowlist: [],
        denylist: [],
      },
    ]);
    const auditService = new ClipboardAuditService();
    const firewall = new AiPromptFirewall(policyEngine);
    const copyService = new SecureCopyService(policyEngine, firewall, auditService, vault);
    const text = "token = 'sk-1234567890abcd'";

    const result = await copyService.copy(text);

    expect(result.blocked).to.be.true;
    expect(result.reason).to.contain("Policy violation");
    expect(auditService.getSummary().blockedCopyAttempts).to.equal(1);
  });

  it("should decrypt valid DevLeakShield tokens during secure paste", async () => {
    const storage = new MockSecretStorage();
    const sessionManager = new SessionManager(storage as any);
    await sessionManager.initialize();
    const masterKey = sessionManager.getMasterKey();

    const vault = new SecureVault(storage as any, masterKey);
    await vault.initialize();

    const auditService = new ClipboardAuditService();
    const pasteService = new SecurePasteService(auditService, vault);
    const secret = "sk-1234567890abcd";
    
    // Store secret in vault first
    const storeResult = await vault.store(secret, "openai", 0.85);
    const payload = `const key = \"${storeResult.token}\";`;

    const result = await pasteService.paste(payload);

    expect(result.success).to.be.true;
    expect(result.text).to.include(secret);
    expect(result.decryptedCount).to.equal(1);
    expect(auditService.getSummary().decryptedPasteCount).to.equal(1);
  });

  it("should fail secure paste when token integrity validation fails", async () => {
    const storage = new MockSecretStorage();
    const sessionManager = new SessionManager(storage as any);
    await sessionManager.initialize();
    const masterKey = sessionManager.getMasterKey();

    const vault = new SecureVault(storage as any, masterKey);
    await vault.initialize();

    const auditService = new ClipboardAuditService();
    const pasteService = new SecurePasteService(auditService, vault);
    const invalidPayload = "DEVLEAKSHIELD_TOKEN_deadbeef-dead-4eef-beef-feeddeadbeef";

    const result = await pasteService.paste(invalidPayload);

    expect(result.success).to.be.false;
    expect(result.blocked).to.be.true;
    expect(result.reason).to.contain("Token not found in vault");
  });
});
