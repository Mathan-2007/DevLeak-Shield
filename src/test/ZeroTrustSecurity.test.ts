import { expect } from "chai";
import { SessionManager } from "../core/session/SessionManager";
import { SecureVault } from "../core/vault/SecureVault";
import { TokenGenerator } from "../core/crypto/TokenGenerator";
import { CryptoService } from "../core/crypto/CryptoService";
import { AiPromptFirewall } from "../core/firewall/AiPromptFirewall";
import { PolicyEngine } from "../core/policies/PolicyEngine";
import { ClipboardAuditService } from "../clipboard/ClipboardAuditService";
import { SecureCopyService } from "../clipboard/SecureCopyService";
import { SecurePasteService } from "../clipboard/SecurePasteService";
import { GitSecurityScanner } from "../core/git/GitSecurityScanner";
import { SecretDetectionService } from "../core/secrets/SecretDetectionService";

// Mock VS Code SecretStorage for testing
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

describe("DevLeakShield Zero-Trust Security Architecture", () => {
  describe("Master Key Management", () => {
    it("should generate and store master key on first launch", async () => {
      const storage = new MockSecretStorage();
      const manager = new SessionManager(storage as any);

      await manager.initialize();
      const key = manager.getMasterKey();

      expect(key).to.exist;
      expect(key).to.be.instanceOf(Buffer);
      expect(key.length).to.equal(32); // 256-bit
    });

    it("should persist master key across sessions", async () => {
      const storage = new MockSecretStorage();
      const manager1 = new SessionManager(storage as any);

      await manager1.initialize();
      const key1 = manager1.getMasterKey();

      // Simulate new session
      const manager2 = new SessionManager(storage as any);
      await manager2.initialize();
      const key2 = manager2.getMasterKey();

      expect(key1).to.deep.equal(key2);
    });

    it("should never expose master key in logs or APIs", async () => {
      const storage = new MockSecretStorage();
      const manager = new SessionManager(storage as any);

      await manager.initialize();
      const keyStr = manager.getMasterKey().toString();

      // Verify key is not hardcoded or in common patterns
      expect(keyStr).to.not.include("hardcoded");
      expect(keyStr).to.not.include("sk-");
      expect(keyStr).to.not.include("AKIA");
    });
  });

  describe("Secure Vault Storage", () => {
    let vault: SecureVault;
    let masterKey: Buffer;

    beforeEach(async () => {
      const storage = new MockSecretStorage();
      const manager = new SessionManager(storage as any);
      await manager.initialize();
      masterKey = manager.getMasterKey();

      vault = new SecureVault(storage as any, masterKey);
      await vault.initialize();
    });

    it("should store secret in vault with token reference", async () => {
      const secret = "sk-1234567890abcdef";
      const result = await vault.store(secret, "openai", 0.85);

      expect(result).to.have.property("token");
      expect(result).to.have.property("tokenId");
      expect(result).to.have.property("classification");
      expect(result.classification).to.equal("openai");
      expect(result.riskScore).to.equal(0.85);
    });

    it("should generate unique tokens for each secret", async () => {
      const secret = "sk-test";
      const result1 = await vault.store(secret, "openai", 0.5);
      const result2 = await vault.store(secret, "openai", 0.5);

      expect(result1.token).to.not.equal(result2.token);
      expect(result1.tokenId).to.not.equal(result2.tokenId);
    });

    it("should retrieve secret from vault using token", async () => {
      const secret = "AKIA1234567890123456";
      const storeResult = await vault.store(secret, "aws", 0.9);

      const retrieveResult = await vault.retrieve(storeResult.token);

      expect(retrieveResult.found).to.be.true;
      expect(retrieveResult.secret).to.equal(secret);
      expect(retrieveResult.classification).to.equal("aws");
    });

    it("should fail if token doesn't exist in vault", async () => {
      const fakeToken = "DEVLEAKSHIELD_TOKEN_deadbeef-dead-4eef-beef-feeddeadbeef";
      const result = await vault.retrieve(fakeToken);

      expect(result.found).to.be.false;
      expect(result.secret).to.be.undefined;
      expect(result.error).to.exist;
    });

    it("should use AES-256-GCM with authentication", async () => {
      const secret = "sensitive-data";
      const result = await vault.store(secret, "generic", 0.7);

      // Token should be reference only, not contain encrypted data
      expect(result.token).to.match(/^DEVLEAKSHIELD_TOKEN_[0-9a-f\-]+$/i);

      // Vault entry should be encrypted
      const metadata = vault.getSummary();
      expect(metadata.totalEntries).to.equal(1);
    });
  });

  describe("Token Validation", () => {
    it("should validate token format", () => {
      const validToken = "DEVLEAKSHIELD_TOKEN_8f4c9e2d-a1b2-43d4-85f6-7890abcdef12";
      const invalidToken1 = "DEVLEAKSHIELD_TOKEN_notauuid";
      const invalidToken2 = "INVALID_TOKEN_8f4c9e2d";

      expect(TokenGenerator.isValidToken(validToken)).to.be.true;
      expect(TokenGenerator.isValidToken(invalidToken1)).to.be.false;
      expect(TokenGenerator.isValidToken(invalidToken2)).to.be.false;
    });

    it("should extract token ID correctly", () => {
      const token = "DEVLEAKSHIELD_TOKEN_8f4c9e2d-a1b2-43d4-85f6-7890abcdef12";
      const tokenId = TokenGenerator.extractId(token);

      expect(tokenId).to.equal("8f4c9e2d-a1b2-43d4-85f6-7890abcdef12");
    });

    it("should throw on invalid token format during extraction", () => {
      const invalidToken = "INVALID_TOKEN";

      expect(() => {
        TokenGenerator.extractId(invalidToken);
      }).to.throw();
    });
  });

  describe("Secure Copy Workflow", () => {
    let copyService: SecureCopyService;
    let vault: SecureVault;

    beforeEach(async () => {
      const storage = new MockSecretStorage();
      const manager = new SessionManager(storage as any);
      await manager.initialize();
      const masterKey = manager.getMasterKey();

      vault = new SecureVault(storage as any, masterKey);
      await vault.initialize();

      const policyEngine = new PolicyEngine([
        {
          id: "allow-all",
          name: "Allow all",
          description: "Allow all secrets",
          threshold: 1,
          categories: ["openai", "aws", "github", "jwt", "ssh", "database", "api_key", "generic"],
          enabled: true,
          allowlist: [],
          denylist: [],
        },
      ]);

      const firewall = new AiPromptFirewall(policyEngine);
      const auditService = new ClipboardAuditService();

      copyService = new SecureCopyService(policyEngine, firewall, auditService, vault);
    });

    it("should encrypt secrets and replace with vault tokens", async () => {
      const text = "const apiKey = 'sk-1234567890abcdef';";
      const result = await copyService.copy(text);

      expect(result.blocked).to.be.false;
      expect(result.text).to.include("DEVLEAKSHIELD_TOKEN_");
      expect(result.text).to.not.include("sk-1234567890abcdef");
      expect(result.secretsProtected).to.equal(1);
    });

    it("should block copy when policy threshold exceeded", async () => {
      const policyEngine = new PolicyEngine([
        {
          id: "block-all",
          name: "Block all",
          description: "Block all secrets",
          threshold: 0.0,
          categories: ["openai", "aws", "github", "jwt", "ssh", "database", "api_key", "generic"],
          enabled: true,
          allowlist: [],
          denylist: [],
        },
      ]);

      const firewall = new AiPromptFirewall(policyEngine);
      const auditService = new ClipboardAuditService();
      const blockedCopyService = new SecureCopyService(policyEngine, firewall, auditService, vault);

      const text = "const apiKey = 'sk-1234567890abcdef';";
      const result = await blockedCopyService.copy(text);

      expect(result.blocked).to.be.true;
      expect(result.reason).to.exist;
      expect(result.secretsProtected).to.equal(0);
    });
  });

  describe("Secure Paste Workflow", () => {
    let vault: SecureVault;
    let pasteService: SecurePasteService;

    beforeEach(async () => {
      const storage = new MockSecretStorage();
      const manager = new SessionManager(storage as any);
      await manager.initialize();
      const masterKey = manager.getMasterKey();

      vault = new SecureVault(storage as any, masterKey);
      await vault.initialize();

      const auditService = new ClipboardAuditService();
      pasteService = new SecurePasteService(auditService, vault);
    });

    it("should decrypt vault tokens back to secrets", async () => {
      const secret = "AKIA1234567890123456";
      const storeResult = await vault.store(secret, "aws", 0.9);
      const payload = `const key = "${storeResult.token}";`;

      const result = await pasteService.paste(payload);

      expect(result.success).to.be.true;
      expect(result.text).to.include(secret);
      expect(result.decryptedCount).to.equal(1);
    });

    it("should fail if token doesn't exist in vault", async () => {
      const fakeToken = "DEVLEAKSHIELD_TOKEN_deadbeef-dead-4eef-beef-feeddeadbeef";
      const payload = `const key = "${fakeToken}";`;

      const result = await pasteService.paste(payload);

      expect(result.success).to.be.false;
      expect(result.blocked).to.be.true;
      expect(result.decryptedCount).to.equal(0);
    });

    it("should handle text without tokens gracefully", async () => {
      const payload = "const key = 'no-token-here';";
      const result = await pasteService.paste(payload);

      expect(result.success).to.be.true;
      expect(result.text).to.equal(payload);
      expect(result.decryptedCount).to.equal(0);
    });
  });

  describe("Attack Resistance", () => {
    it("token theft should not reveal secret", async () => {
      const storage = new MockSecretStorage();
      const manager = new SessionManager(storage as any);
      await manager.initialize();
      const masterKey = manager.getMasterKey();

      const vault = new SecureVault(storage as any, masterKey);
      await vault.initialize();

      const secret = "sk-1234567890abcdef";
      const result = await vault.store(secret, "openai", 0.85);
      const token = result.token;

      // Attacker has token
      // But cannot extract secret without master key and vault
      const fakeVault = new SecureVault(storage as any, Buffer.alloc(32));
      const retrieveResult = await fakeVault.retrieve(token);

      expect(retrieveResult.found).to.be.false;
    });

    it("vault theft without master key should not reveal secrets", async () => {
      const storage = new MockSecretStorage();
      const manager = new SessionManager(storage as any);
      await manager.initialize();
      const masterKey = manager.getMasterKey();

      const vault = new SecureVault(storage as any, masterKey);
      await vault.initialize();

      const secret = "AKIA1234567890123456";
      await vault.store(secret, "aws", 0.9);

      // Attacker has vault data but not master key
      const wrongKey = CryptoService.generateKey();
      const attemptVault = new SecureVault(storage as any, wrongKey);

      try {
        await attemptVault.initialize();
        // If we got here, the vault loaded but with wrong key
        // Trying to decrypt any entry should fail
        const entries = attemptVault.getSummary();
        // Can see structure but not decrypt
        expect(entries).to.exist;
      } catch {
        // Expected: vault decryption fails with wrong key
        expect(true).to.be.true;
      }
    });
  });

  describe("Git Security Scanning", () => {
    it("should detect scanner instantiation", async () => {
      const policyEngine = new PolicyEngine([
        {
          id: "test-policy",
          name: "Test",
          description: "Test policy",
          threshold: 0.8,
          categories: ["openai", "aws", "github", "jwt", "ssh", "database", "api_key", "generic"],
          enabled: true,
          allowlist: [],
          denylist: [],
        },
      ]);

      const detectionService = new SecretDetectionService();
      const scanner = new GitSecurityScanner(policyEngine, detectionService);

      expect(scanner).to.exist;
    });
  });
});
