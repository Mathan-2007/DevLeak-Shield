"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.TokenGenerator = void 0;
const crypto = require("crypto");
/**
 * TokenGenerator: Generates cryptographically secure vault references
 * Tokens contain ONLY a random ID, never the secret or encryption key
 * Token format: DEVLEAKSHIELD_TOKEN_<uuid>
 * Example: DEVLEAKSHIELD_TOKEN_8f4c9e2d-a1b2-c3d4-e5f6-7890abcdef12
 */
class TokenGenerator {
    /**
     * Generate a unique vault reference token
     * @returns Token format: DEVLEAKSHIELD_TOKEN_<uuid>
     */
    static generate() {
        // Generate UUID v4
        const uuid = crypto.randomUUID();
        return `DEVLEAKSHIELD_TOKEN_${uuid}`;
    }
    /**
     * Extract token ID from full token
     * @param token Full token like "DEVLEAKSHIELD_TOKEN_8f4c9e2d"
     * @returns Just the ID part: "8f4c9e2d"
     */
    static extractId(token) {
        const match = token.match(/DEVLEAKSHIELD_TOKEN_(.+)/);
        if (!match || !match[1]) {
            throw new Error("Invalid token format");
        }
        return match[1];
    }
    /**
     * Check if string is a valid vault token
     */
    static isValidToken(token) {
        return /^DEVLEAKSHIELD_TOKEN_[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(token);
    }
}
exports.TokenGenerator = TokenGenerator;
//# sourceMappingURL=TokenGenerator.js.map