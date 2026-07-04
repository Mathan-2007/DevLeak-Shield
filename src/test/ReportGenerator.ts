import { ReportGenerator as CoreReportGenerator } from "../core/reports/ReportGenerator";

export class ReportGenerator {
  static generateJson(findings: any[]) {
    return new CoreReportGenerator().generateJson(findings as any);
  }

  static generateCsv(findings: any[]) {
    return new CoreReportGenerator().generateCsv(findings as any);
  }

  static generateHtml(findings: any[]) {
    return new CoreReportGenerator().generateHtml(findings as any);
  }
}
