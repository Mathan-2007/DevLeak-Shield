import { ClipboardAuditRecord, ClipboardAuditSummary } from "../types";

export class ClipboardAuditService {
  private readonly records: ClipboardAuditRecord[] = [];

  log(record: ClipboardAuditRecord): void {
    this.records.push(record);
  }

  getRecords(): ClipboardAuditRecord[] {
    return [...this.records];
  }

  getSummary(): ClipboardAuditSummary {
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
