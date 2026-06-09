import * as vscode from "vscode";
import { detectSecrets } from "./secretDetector";
import { encodeSecret } from "./encoder";
import { decodeSecret } from "./decoder";
import { getSessionKey } from "./cryptoSession"; // Temporarily use this until full refactor

export async function lockWorkspace() {

    const files = await vscode.workspace.findFiles("**/*");

    for (const file of files) {

        try {
            const document = await vscode.workspace.openTextDocument(file);
            let text = document.getText();

            const rawSecrets = detectSecrets(text);
            const secrets = Array.from(new Set(rawSecrets));

            if (secrets.length === 0) continue;

            for (const secret of secrets) {
                if (secret.startsWith("HIDDEN_SECRET_DO_NOT_DECODE_")) continue;

                const encoded = encodeSecret(secret);
                text = text.replaceAll(secret, encoded);
            }

            const edit = new vscode.WorkspaceEdit();
            edit.replace(
                file,
                new vscode.Range(
                    document.positionAt(0),
                    document.positionAt(document.getText().length)
                ),
                text
            );

            await vscode.workspace.applyEdit(edit);

        } catch (err) {
            console.log("Lock failed for file:", file.fsPath, err);
        }
    }

    vscode.window.showInformationMessage("Workspace fully locked 🔒");
}

/*
UNLOCK WORKSPACE
Decodes the encrypted placeholders and saves real keys back to disk.
*/
export async function unlockWorkspace() {

    const files = await vscode.workspace.findFiles("**/*");

    for (const file of files) {

        try {
            const document = await vscode.workspace.openTextDocument(file);
            let text = document.getText();

            const matches = text.match(/HIDDEN_SECRET[A-Za-z0-9+/=]+:[A-Za-z0-9+/=]+/g);

            if (!matches) continue;

            const tokens = Array.from(new Set(matches));

            for (const token of tokens) {
                try {
                    const original = decodeSecret(token);
                    text = text.replaceAll(token, original);
                } catch (err) {
                    console.log("Decode failed:", err);
                }
            }

            const edit = new vscode.WorkspaceEdit();
            edit.replace(
                file,
                new vscode.Range(
                    document.positionAt(0),
                    document.positionAt(document.getText().length)
                ),
                text
            );

            await vscode.workspace.applyEdit(edit);

        } catch (err) {
            console.log("Unlock failed for file:", file.fsPath, err);
        }
    }

    vscode.window.showInformationMessage("Workspace fully unlocked 🔓");
}