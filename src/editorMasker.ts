import * as vscode from "vscode";
import { detectSecrets } from "./secretDetector";
import { encodeSecret } from "./encoder";
import { decodeSecret } from "./decoder";
import { getSessionKey } from "./cryptoSession"; // Temporarily use this until full refactor

/*
Store mapping between encoded value and original secret
*/
const maskedSecrets: Map<string, string> = new Map();

/*
MASK SECRETS IN EDITOR
This replaces secrets with encrypted tokens
*/
export async function maskEditorSecrets(editor: vscode.TextEditor) {

    const document = editor.document;
    const text = document.getText();

    const rawSecrets = detectSecrets(text);
    // Deduplicate secrets to avoid overlapping edit exceptions
    const secrets = Array.from(new Set(rawSecrets));

    if (secrets.length === 0) return;

    await editor.edit(editBuilder => {

        for (const secret of secrets) {

            if (secret.startsWith("HIDDEN_SECRET_DO_NOT_DECODE_")) continue;

            const encoded = encodeSecret(secret);

            maskedSecrets.set(encoded, secret);

            let index = text.indexOf(secret);

            while (index !== -1) {

                const start = document.positionAt(index);
                const end = document.positionAt(index + secret.length);

                editBuilder.replace(new vscode.Range(start, end), encoded);

                index = text.indexOf(secret, index + secret.length);
            }

        }

    });

}

/*
RESTORE ORIGINAL SECRETS
Returns an array of TextEdits to be used with event.waitUntil() 
*/
export async function restoreEditorSecrets(editor: vscode.TextEditor): Promise<vscode.TextEdit[]> {

    const document = editor.document;
    const text = document.getText();
    const edits: vscode.TextEdit[] = [];

    for (const [encoded, original] of maskedSecrets.entries()) {
        let index = text.indexOf(encoded);

        while (index !== -1) {
            const start = document.positionAt(index);
            const end = document.positionAt(index + encoded.length);

            edits.push(vscode.TextEdit.replace(new vscode.Range(start, end), original));

            index = text.indexOf(encoded, index + encoded.length);
        }
    }

    return edits;
}