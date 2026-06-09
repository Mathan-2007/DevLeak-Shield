"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.NotificationService = void 0;
const vscode = require("vscode");
class NotificationService {
    static showError(message) {
        vscode.window.showErrorMessage(message);
    }
}
exports.NotificationService = NotificationService;
//# sourceMappingURL=NotificationService.js.map