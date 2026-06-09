import * as vscode from 'vscode';

export class NotificationService {
    public static showError(message: string): void {
        vscode.window.showErrorMessage(message);
    }
}