"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.SecurityDashboardService = void 0;
class SecurityDashboardService {
    constructor() {
        this.history = [];
    }
    recordSummary(summary) {
        this.history.push(summary);
        if (this.history.length > 100) {
            this.history.shift();
        }
    }
    getCurrentScore() {
        if (this.history.length === 0)
            return 100;
        return Number((this.history[this.history.length - 1].score).toFixed(2));
    }
    getRiskDistribution() {
        const distribution = {};
        this.history.forEach((summary) => {
            Object.entries(summary.riskDistribution).forEach(([category, count]) => {
                distribution[category] = (distribution[category] ?? 0) + count;
            });
        });
        return distribution;
    }
    getHistoricalAnalytics() {
        return [...this.history];
    }
    static buildSummary(findings) {
        const riskDistribution = findings.reduce((acc, finding) => {
            acc[finding.category] = (acc[finding.category] ?? 0) + 1;
            return acc;
        }, {});
        const score = findings.length === 0
            ? 100
            : Number((100 - Math.min(100, findings.reduce((sum, item) => sum + item.detection.risk * 100, 0) / findings.length)).toFixed(2));
        return {
            totalFindings: findings.length,
            riskDistribution,
            score,
            generatedAt: new Date().toISOString(),
        };
    }
}
exports.SecurityDashboardService = SecurityDashboardService;
//# sourceMappingURL=SecurityDashboardService.js.map