"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.ClipboardAuditService = void 0;
class ClipboardAuditService {
    constructor() {
        this.records = [];
    }
    log(record) {
        this.records.push(record);
    }
    getRecords() {
        return [...this.records];
    }
    getSummary() {
        const totalEvents = this.records.length;
        const blockedCopyAttempts = this.records.filter((record) => record.action === "blocked_copy").length;
        const decryptedPasteCount = this.records.filter((record) => record.action === "secure_paste" && record.success).length;
        const encryptedSecretsCount = this.records
            .filter((record) => record.action === "secure_copy" && record.success)
            .reduce((sum, record) => sum + record.itemCount, 0);
        return {
            totalEvents,
            blockedCopyAttempts,
            encryptedSecretsCount,
            decryptedPasteCount,
        };
    }
}
exports.ClipboardAuditService = ClipboardAuditService;
//# sourceMappingURL=ClipboardAuditService.js.map