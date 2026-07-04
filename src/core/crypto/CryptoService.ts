import * as crypto from "crypto";

const ALGORITHM = "aes-256-gcm";
const IV_LENGTH = 12;
const SALT_LENGTH = 16;
const TAG_LENGTH = 16;

export class CryptoService {
  generateKey(): Buffer {
    return CryptoService.generateKey();
  }

  deriveKey(password: string, salt: Buffer): Buffer {
    return CryptoService.deriveKey(password, salt);
  }

  encrypt(plainText: string, key: Buffer): string {
    return CryptoService.encrypt(plainText, key);
  }

  decrypt(cipherText: string, key: Buffer): string {
    return CryptoService.decrypt(cipherText, key);
  }

  hash(input: string): string {
    return CryptoService.hash(input);
  }

  static generateKey(): Buffer {
    return crypto.randomBytes(32);
  }

  static deriveKey(password: string, salt: Buffer): Buffer {
    return crypto.pbkdf2Sync(password, salt, 200000, 32, "sha512");
  }

  static encrypt(plainText: string, key: Buffer): string {
    const iv = crypto.randomBytes(IV_LENGTH);
    const cipher = crypto.createCipheriv(ALGORITHM, key, iv);
    const encrypted = Buffer.concat([cipher.update(plainText, "utf8"), cipher.final()]);
    const authTag = cipher.getAuthTag();
    return Buffer.concat([iv, authTag, encrypted]).toString("base64");
  }

  static decrypt(cipherText: string, key: Buffer): string {
    const data = Buffer.from(cipherText, "base64");
    const iv = data.slice(0, IV_LENGTH);
    const authTag = data.slice(IV_LENGTH, IV_LENGTH + TAG_LENGTH);
    const encrypted = data.slice(IV_LENGTH + TAG_LENGTH);
    const decipher = crypto.createDecipheriv(ALGORITHM, key, iv);
    decipher.setAuthTag(authTag);
    const decrypted = Buffer.concat([decipher.update(encrypted), decipher.final()]);
    return decrypted.toString("utf8");
  }

  static hash(input: string): string {
    return crypto.createHash("sha256").update(input, "utf8").digest("hex");
  }
}
