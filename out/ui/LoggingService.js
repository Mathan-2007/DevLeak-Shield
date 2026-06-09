"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.LoggingService = void 0;
const vscode = require("vscode");
class LoggingService {
    static get outputChannel() {
        if (!this._outputChannel) {
            this._outputChannel = vscode.window.createOutputChannel('DevLeakShield');
        }
        return this._outputChannel;
    }
    static log(message) {
        const timestamp = new Date().toLocaleTimeString();
        this.outputChannel.appendLine(`[${timestamp}] ${message}`);
    }
    static dispose() {
        this._outputChannel?.dispose();
    }
}
exports.LoggingService = LoggingService;
//# sourceMappingURL=LoggingService.js.map