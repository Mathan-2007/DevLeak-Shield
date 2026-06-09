import * as vscode from 'vscode';

export class NotificationService {
    public static showError(message: string): void {
        vscode.window.showErrorMessage(message);
    }

    public static showInformation(message: string): void {
        vscode.window.showInformationMessage(message);
    }
}
