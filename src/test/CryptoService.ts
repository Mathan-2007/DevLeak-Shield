import * as crypto from "crypto";
import { CryptoService as CoreCryptoService } from "../core/crypto/CryptoService";

function normalizeKey(key: string | Buffer): Buffer {
  if (typeof key === "string") {
    try {
      return Buffer.from(key, "hex");
    } catch {
      return crypto.createHash("sha256").update(key, "utf8").digest();
    }
  }
  return key;
}

export class CryptoService {
  generateKey(): string {
    return CryptoService.generateKey();
  }

  deriveKey(password: string, salt: Buffer): Buffer {
    return CryptoService.deriveKey(password, salt);
  }

  encrypt(plainText: string, key: string | Buffer): string {
    return CryptoService.encrypt(plainText, key);
  }

  decrypt(cipherText: string, key: string | Buffer): string {
    return CryptoService.decrypt(cipherText, key);
  }

  hash(input: string): string {
    return CryptoService.hash(input);
  }

  static generateKey(): string {
    return CoreCryptoService.generateKey().toString("hex");
  }

  static deriveKey(password: string, salt: Buffer): Buffer {
    return CoreCryptoService.deriveKey(password, salt);
  }

  static encrypt(plainText: string, key: string | Buffer): string {
    return CoreCryptoService.encrypt(plainText, normalizeKey(key));
  }

  static decrypt(cipherText: string, key: string | Buffer): string {
    return CoreCryptoService.decrypt(cipherText, normalizeKey(key));
  }

  static hash(input: string): string {
    return CoreCryptoService.hash(input);
  }
}
