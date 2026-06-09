import * as vscode from 'vscode';

export class LoggingService {
    private static _outputChannel: vscode.OutputChannel;

    private static get outputChannel(): vscode.OutputChannel {
        if (!this._outputChannel) {
            this._outputChannel = vscode.window.createOutputChannel('DevLeakShield');
        }
        return this._outputChannel;
    }

    public static log(message: string): void {
        const timestamp = new Date().toLocaleTimeString();
        this.outputChannel.appendLine(`[${timestamp}] ${message}`);
    }

    public static dispose(): void {
        this._outputChannel?.dispose();
    }
}