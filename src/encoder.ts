import * as crypto from "crypto";
import { getSessionKey } from "./cryptoSession";
import { CryptoService } from "./core/crypto/CryptoService"; // Assuming CryptoService is the canonical encryption method

/*
Encrypt a secret using AES-256
Returns: HIDDEN_SECRET_DO_NOT_DECODE_<IV>:<encrypted_data>
*/
export function encodeSecret(secret: string): string {

    // Use deterministic IV (md5 hash of secret produces exactly 16 bytes)
    // This guarantees the string is encrypted without random fluctuations
    const iv = crypto.createHash("md5").update(secret).digest();

    const sessionKey = getSessionKey();

    const cipher = crypto.createCipheriv(
        "aes-256-cbc",
        sessionKey,
        iv
    );

    let encrypted = cipher.update(secret, "utf8", "base64");
    encrypted += cipher.final("base64");

    const ivString = iv.toString("base64");

    return `HIDDEN_SECRET_DO_NOT_DECODE_${ivString}:${encrypted}`;
}