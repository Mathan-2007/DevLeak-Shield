import * as vscode from "vscode";
import { CryptoService } from "../crypto/CryptoService";

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
export class SessionManager {
  private masterKey?: Buffer;
  private readonly MASTER_KEY_STORE_KEY = "devLeakShield.masterKey";

  constructor(private readonly secretStorage: vscode.SecretStorage) {}

  /**
   * Initialize: Load or generate master key from VS Code SecretStorage
   */
  async initialize(): Promise<void> {
    const storedKey = await this.secretStorage.get(this.MASTER_KEY_STORE_KEY);

    if (storedKey) {
      this.masterKey = Buffer.from(storedKey, "base64");
      return;
    }

    // Generate new 256-bit master key on first launch
    this.masterKey = CryptoService.generateKey();
    await this.secretStorage.store(this.MASTER_KEY_STORE_KEY, this.masterKey.toString("base64"));
  }

  /**
   * Get master key for vault operations
   * Throws if not initialized
   */
  getMasterKey(): Buffer {
    if (!this.masterKey) {
      throw new Error("SessionManager not initialized. Call initialize() first.");
    }
    return this.masterKey;
  }

  /**
   * Legacy method for backward compatibility
   */
  getKey(): Buffer {
    return this.getMasterKey();
  }
}
