"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.SecureVault = void 0;
const CryptoService_1 = require("../crypto/CryptoService");
const TokenGenerator_1 = require("../crypto/TokenGenerator");
/**
 * SecureVault: Zero-trust enterprise vault architecture
 *
 * Design:
 * - Master key stored in VS Code SecretStorage (never in plaintext files)
 * - Vault entries encrypted with master key using AES-256-GCM
 * - Tokens contain only vault reference ID (never the secret)
 * - Each entry has IV, authTag, metadata, classification, riskScore
 * - Token theft cannot recover secret without master key
 * - Vault theft cannot decrypt secrets without master key
 *
 * Storage: VS Code SecretStorage (encrypted at rest by OS)
 * Entry format: {tokenId -> encrypted VaultEntry}
 */
class SecureVault {
    constructor(secretStorage, masterKey) {
        this.secretStorage = secretStorage;
        this.VAULT_KEY = "devLeakShield.vault";
        this.VAULT_METADATA_KEY = "devLeakShield.vaultMetadata";
        this.entries = new Map();
        this.masterKey = masterKey;
    }
    /**
     * Initialize vault: Load existing entries from SecretStorage
     */
    async initialize() {
        if (!this.masterKey) {
            throw new Error("Vault master key not available");
        }
        try {
            const storedData = await this.secretStorage.get(this.VAULT_KEY);
            if (!storedData) {
                // Fresh vault
                this.entries = new Map();
                await this.saveMetadata();
                return;
            }
            // Decrypt and parse vault entries
            const decrypted = CryptoService_1.CryptoService.decrypt(storedData, this.masterKey);
            const parsed = JSON.parse(decrypted);
            this.entries = new Map(Object.entries(parsed));
        }
        catch (error) {
            throw new Error(`Vault initialization failed: ${error instanceof Error ? error.message : String(error)}`);
        }
    }
    /**
     * Store secret in vault, return vault reference token
     *
     * Flow:
     * 1. Generate unique token ID
     * 2. Encrypt secret with master key (AES-256-GCM)
     * 3. Store encrypted entry in vault
     * 4. Return token (never contains secret)
     *
     * @param secret The plaintext secret to protect
     * @param classification Secret category (openai, aws, github, etc.)
     * @param riskScore Risk score 0.0-1.0
     * @returns VaultStoreResult with token (DEVLEAKSHIELD_TOKEN_<id>)
     */
    async store(secret, classification, riskScore, metadata) {
        if (!this.masterKey) {
            throw new Error("Vault not initialized");
        }
        // Generate unique token ID
        const token = TokenGenerator_1.TokenGenerator.generate();
        const tokenId = TokenGenerator_1.TokenGenerator.extractId(token);
        // Create vault entry: encrypt secret with master key
        const entry = {
            tokenId,
            encryptedSecret: CryptoService_1.CryptoService.encrypt(secret, this.masterKey),
            createdAt: new Date().toISOString(),
            classification,
            riskScore,
            metadata,
        };
        // Store in memory vault
        this.entries.set(tokenId, entry);
        // Persist to SecretStorage
        await this.persist();
        // Return token (no secret data)
        return {
            token,
            tokenId,
            classification,
            riskScore,
        };
    }
    /**
     * Retrieve secret from vault using token
     *
     * Flow:
     * 1. Extract token ID from token
     * 2. Look up entry in vault
     * 3. Decrypt secret with master key
     * 4. Return secret only if entry exists
     * 5. Return error if token invalid or vault entry missing
     *
     * @param token The vault reference token (DEVLEAKSHIELD_TOKEN_<id>)
     * @returns VaultRetrieveResult with secret or error
     */
    async retrieve(token) {
        try {
            if (!TokenGenerator_1.TokenGenerator.isValidToken(token)) {
                return {
                    found: false,
                    error: "Invalid token format",
                };
            }
            const tokenId = TokenGenerator_1.TokenGenerator.extractId(token);
            const entry = this.entries.get(tokenId);
            if (!entry) {
                return {
                    found: false,
                    error: "Token not found in vault",
                };
            }
            if (!this.masterKey) {
                return {
                    found: false,
                    error: "Vault not initialized",
                };
            }
            // Decrypt secret
            const decrypted = CryptoService_1.CryptoService.decrypt(entry.encryptedSecret, this.masterKey);
            return {
                found: true,
                secret: decrypted,
                classification: entry.classification,
                riskScore: entry.riskScore,
            };
        }
        catch (error) {
            return {
                found: false,
                error: `Decryption failed: ${error instanceof Error ? error.message : String(error)}`,
            };
        }
    }
    /**
     * Delete entry from vault
     * Useful for cleanup after paste or on command
     */
    async delete(token) {
        try {
            const tokenId = TokenGenerator_1.TokenGenerator.extractId(token);
            const deleted = this.entries.delete(tokenId);
            if (deleted) {
                await this.persist();
            }
            return deleted;
        }
        catch {
            return false;
        }
    }
    /**
     * Get vault statistics (no secret exposure)
     */
    getSummary() {
        const categories = {};
        let totalRisk = 0;
        for (const entry of this.entries.values()) {
            categories[entry.classification] = (categories[entry.classification] ?? 0) + 1;
            totalRisk += entry.riskScore;
        }
        return {
            totalEntries: this.entries.size,
            entriesByCategory: categories,
            averageRiskScore: this.entries.size > 0 ? totalRisk / this.entries.size : 0,
        };
    }
    /**
     * Encrypt and persist vault to SecretStorage
     * All entries are protected by master key (AES-256-GCM)
     * @private
     */
    async persist() {
        if (!this.masterKey) {
            throw new Error("Vault not initialized");
        }
        const entriesObject = Object.fromEntries(this.entries);
        const json = JSON.stringify(entriesObject);
        const encrypted = CryptoService_1.CryptoService.encrypt(json, this.masterKey);
        await this.secretStorage.store(this.VAULT_KEY, encrypted);
        await this.saveMetadata();
    }
    /**
     * Save vault metadata (not encrypted, no sensitive data)
     * @private
     */
    async saveMetadata() {
        const metadata = {
            version: 1,
            entriesCount: this.entries.size,
            createdAt: new Date().toISOString(),
            lastModified: new Date().toISOString(),
        };
        await this.secretStorage.store(this.VAULT_METADATA_KEY, JSON.stringify(metadata));
    }
}
exports.SecureVault = SecureVault;
//# sourceMappingURL=SecureVault.js.map