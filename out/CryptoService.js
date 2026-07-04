"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.CryptoService = void 0;
const CryptoService_1 = require("./core/crypto/CryptoService");
class CryptoService {
    generateKey() {
        return CryptoService.generateKey();
    }
    deriveKey(password, salt) {
        return CryptoService.deriveKey(password, salt);
    }
    encrypt(plainText, key) {
        return CryptoService.encrypt(plainText, key);
    }
    decrypt(cipherText, key) {
        return CryptoService.decrypt(cipherText, key);
    }
    hash(input) {
        return CryptoService.hash(input);
    }
    static generateKey() {
        return CryptoService_1.CryptoService.generateKey();
    }
    static deriveKey(password, salt) {
        return CryptoService_1.CryptoService.deriveKey(password, salt);
    }
    static encrypt(plainText, key) {
        return CryptoService_1.CryptoService.encrypt(plainText, key);
    }
    static decrypt(cipherText, key) {
        return CryptoService_1.CryptoService.decrypt(cipherText, key);
    }
    static hash(input) {
        return CryptoService_1.CryptoService.hash(input);
    }
}
exports.CryptoService = CryptoService;
//# sourceMappingURL=CryptoService.js.map