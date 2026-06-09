import * as vscode from "vscode";

export class StatusBarManager {
  private readonly items: vscode.StatusBarItem[] = [];

  constructor(private readonly context: vscode.ExtensionContext) {}

  createItem(text: string, command: string, alignment: vscode.StatusBarAlignment, priority = 0, tooltip?: string): vscode.StatusBarItem {
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

  dispose(): void {
    this.items.forEach((item) => item.dispose());
  }
}
