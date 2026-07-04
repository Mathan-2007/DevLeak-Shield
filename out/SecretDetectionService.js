"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.SecretDetectionService = void 0;
const SecretDetectionService_1 = require("./core/secrets/SecretDetectionService");
class SecretDetectionService extends SecretDetectionService_1.SecretDetectionService {
    constructor(customRules = []) {
        super(customRules);
    }
    scan(text, filePath) {
        return this.detect(text, filePath).findings;
    }
}
exports.SecretDetectionService = SecretDetectionService;
//# sourceMappingURL=SecretDetectionService.js.map