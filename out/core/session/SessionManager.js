"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.SessionManager = void 0;
const CryptoService_1 = require("../crypto/CryptoService");
/**
 * SessionManager: Single source of truth for master key management
 *
 * Design:
 * - Master key (256-bit) stored in VS Code SecretStorage
 * - Generated on first launch, persists across restarts
 * - Used to encrypt/decrypt all vault entries
 * - Never stored in plaintext files
 * - Never exposed in logs
 * - Never hardcoded
 */
class SessionManager {
    constructor(secretStorage) {
        this.secretStorage = secretStorage;
        this.MASTER_KEY_STORE_KEY = "devLeakShield.masterKey";
    }
    /**
     * Initialize: Load or generate master key from VS Code SecretStorage
     */
    async initialize() {
        const storedKey = await this.secretStorage.get(this.MASTER_KEY_STORE_KEY);
        if (storedKey) {
            this.masterKey = Buffer.from(storedKey, "base64");
            return;
        }
        // Generate new 256-bit master key on first launch
        this.masterKey = CryptoService_1.CryptoService.generateKey();
        await this.secretStorage.store(this.MASTER_KEY_STORE_KEY, this.masterKey.toString("base64"));
    }
    /**
     * Get master key for vault operations
     * Throws if not initialized
     */
    getMasterKey() {
        if (!this.masterKey) {
            throw new Error("SessionManager not initialized. Call initialize() first.");
        }
        return this.masterKey;
    }
    /**
     * Legacy method for backward compatibility
     */
    getKey() {
        return this.getMasterKey();
    }
}
exports.SessionManager = SessionManager;
//# sourceMappingURL=SessionManager.js.map