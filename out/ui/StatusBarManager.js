"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.StatusBarManager = void 0;
const vscode = require("vscode");
class StatusBarManager {
    constructor(context) {
        this.context = context;
        this.items = [];
    }
    createItem(text, command, alignment, priority = 0, tooltip) {
        const item = vscode.window.createStatusBarItem(alignment, priority);
        item.text = text;
        item.command = command;
        if (tooltip) {
            item.tooltip = tooltip;
        }
        item.show();
        this.context.subscriptions.push(item);
        this.items.push(item);
        return item;
    }
    dispose() {
        this.items.forEach((item) => item.dispose());
    }
}
exports.StatusBarManager = StatusBarManager;
//# sourceMappingURL=StatusBarManager.js.map