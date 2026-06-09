import { ClipboardAuditService } from "./ClipboardAuditService";
import { SecureVault } from "../core/vault/SecureVault";

export interface SecurePasteResult {
  text: string;
  success: boolean;
  blocked?: boolean;
  reason?: string;
  decryptedCount: number;
}

/**
 * SecurePasteService: Zero-trust secure paste with vault lookup
 *
 * Workflow:
 * 1. Extract vault reference tokens from clipboard text
 * 2. Look up each token in vault
 * 3. Validate token exists and entry is valid
 * 4. Decrypt secret using vault (master key protected)
 * 5. Replace token with original secret
 * 6. Log paste event
 *
 * Security:
 * - Token lookup fails if entry doesn't exist
 * - Decryption only succeeds with valid master key
 * - Token theft cannot recover secret
 * - Failed decryption blocks the entire paste
 */
export class SecurePasteService {
  constructor(
    private readonly auditService: ClipboardAuditService,
    private readonly vault: SecureVault
  ) {}

  async paste(text: string): Promise<SecurePasteResult> {
    const tokens = this.extractTokens(text);

    if (tokens.length === 0) {
      return { text, success: true, decryptedCount: 0 };
    }

    let decodedText = text;
    let decryptedCount = 0;
    const failedTokens: string[] = [];

    for (const token of Array.from(new Set(tokens))) {
      try {
        // Look up token in vault (master key protected)
        const result = await this.vault.retrieve(token);

        if (!result.found || !result.secret) {
          const reason = result.error || "Token not found in vault";
          failedTokens.push(`${token}: ${reason}`);
          continue;
        }

        // Replace token with decrypted secret
        decodedText = decodedText.replaceAll(token, result.secret);
        decryptedCount += 1;
      } catch (error) {
        const reason = `Token integrity validation failed: ${error instanceof Error ? error.message : String(error)}`;
        failedTokens.push(`${token}: ${reason}`);
      }
    }

    // If any tokens failed decryption, block the entire paste
    if (failedTokens.length > 0) {
      const reason = `Vault token decryption failed: ${failedTokens.join("; ")}`;
      this.auditService.log({
        action: "blocked_paste",
        timestamp: new Date().toISOString(),
        riskScore: 1,
        secretTypes: [],
        success: false,
        reason,
        itemCount: tokens.length,
      });
      return { text, success: false, blocked: true, reason, decryptedCount: 0 };
    }

    // Log successful paste
    this.auditService.log({
      action: "secure_paste",
      timestamp: new Date().toISOString(),
      riskScore: 0,
      secretTypes: [],
      success: true,
      itemCount: decryptedCount,
    });

    return { text: decodedText, success: true, decryptedCount };
  }

  /**
   * Extract vault reference tokens from text
   * Token format: DEVLEAKSHIELD_TOKEN_<uuid>
   */
  extractTokens(text: string): string[] {
    const matches = text.match(/DEVLEAKSHIELD_TOKEN_[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}/gi);
    return matches ?? [];
  }
}
