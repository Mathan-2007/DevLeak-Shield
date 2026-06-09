import * as vscode from "vscode";
import { detectSecrets } from "./secretDetector";
import { encodeSecret } from "./encoder";
import { decodeSecret } from "./decoder";

/*
SECURE COPY
Encodes secrets before copying to clipboard.
*/
export async function secureCopy(showPreview = false) {

    const editor = vscode.window.activeTextEditor;
    if (!editor) return;

    let selection = editor.selection;
    let text = "";

    if (selection.isEmpty) {
        const line = editor.document.lineAt(selection.active.line);
        text = line.text;
    } else {
        text = editor.document.getText(selection);
    }

    const secrets = detectSecrets(text);

    for (let secret of secrets) {
        if (secret.startsWith("HIDDEN_SECRET_DO_NOT_DECODE_")) continue;

        const encoded = encodeSecret(secret);
        text = text.replaceAll(secret, encoded);
    }

    await vscode.env.clipboard.writeText(text);

    if (showPreview) {
        const preview = await vscode.workspace.openTextDocument({ content: text, language: "text" });
        await vscode.window.showTextDocument(preview, { preview: true });
    } else {
        vscode.window.showInformationMessage(
            "DevLeakShield: secrets encoded before copy"
        );
    }
}
/*
SECURE PASTE
Decodes encrypted tokens when pasting
*/
export async function securePaste() {

    const editor = vscode.window.activeTextEditor;
    if (!editor) return;

    let text = await vscode.env.clipboard.readText();

    const matches = text.match(/HIDDEN_SECRET_DO_NOT_DECODE_[A-Za-z0-9+/=]+:[A-Za-z0-9+/=]+/g);

    if (matches) {
        for (let token of matches) {
            try {
                const decoded = decodeSecret(token);
                text = text.replaceAll(token, decoded);
            } catch (err) {
                console.log("DevLeakShield decode failed:", err);
            }
        }
    }

    editor.edit(editBuilder => {
        editBuilder.replace(editor.selection, text);
    });
}

/*
ENCRYPT SELECTION IN EDITOR
Replaces the selected text or current line with encrypted tokens.
*/
export async function encryptSelectionInEditor() {

    const editor = vscode.window.activeTextEditor;
    if (!editor) return;

    let selection = editor.selection;
    let range: vscode.Range;
    let text: string;

    if (selection.isEmpty) {
        const line = editor.document.lineAt(selection.active.line);
        range = line.range;
        text = line.text;
    } else {
        range = new vscode.Range(selection.start, selection.end);
        text = editor.document.getText(range);
    }

    const secrets = detectSecrets(text);
    if (secrets.length === 0) {
        vscode.window.showInformationMessage("DevLeakShield: no secrets found to encrypt in selection.");
        return;
    }

    for (let secret of secrets) {
        if (secret.startsWith("HIDDEN_SECRET_DO_NOT_DECODE_")) continue;
        const encoded = encodeSecret(secret);
        text = text.replaceAll(secret, encoded);
    }

    await editor.edit(editBuilder => {
        editBuilder.replace(range, text);
    });

    vscode.window.showInformationMessage("DevLeakShield: selection encrypted in place.");
}

/*
DECRYPT SELECTION IN EDITOR
Restores hidden secret tokens inside the selected text or current line.
*/
export async function decryptSelectionInEditor() {

    const editor = vscode.window.activeTextEditor;
    if (!editor) return;

    let selection = editor.selection;
    let range: vscode.Range;
    let text: string;

    if (selection.isEmpty) {
        const line = editor.document.lineAt(selection.active.line);
        range = line.range;
        text = line.text;
    } else {
        range = new vscode.Range(selection.start, selection.end);
        text = editor.document.getText(range);
    }

    const matches = text.match(/HIDDEN_SECRET_DO_NOT_DECODE_[A-Za-z0-9+/=]+:[A-Za-z0-9+/=]+/g);
    if (!matches) {
        vscode.window.showInformationMessage("DevLeakShield: no encrypted tokens found to decrypt.");
        return;
    }

    for (let token of Array.from(new Set(matches))) {
        try {
            const decoded = decodeSecret(token);
            text = text.replaceAll(token, decoded);
        } catch (err) {
            console.log("DevLeakShield decrypt failed:", err);
        }
    }

    await editor.edit(editBuilder => {
        editBuilder.replace(range, text);
    });

    vscode.window.showInformationMessage("DevLeakShield: selection decrypted in place.");
}
