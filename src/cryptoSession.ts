import * as vscode from "vscode";
import * as crypto from "crypto";
import { SessionManager } from "./core/session/SessionManager"; // Import SessionManager


/*
Initializes the master encryption key from VS Code's secure keychain.
Generates a new one if it is the first time running.
*/
let SESSION_KEY: Buffer;

export function initCryptoSession() {
    if (!SESSION_KEY) {
        console.log("DevLeakShield: Generating TEMP session key");
        SESSION_KEY = crypto.randomBytes(32);
    }
}
/*
Retrieves the loaded session key synchronously
*/
export function getSessionKey(): Buffer {
    if (!SESSION_KEY) {
        throw new Error("Session key not initialized");
    }
    return SESSION_KEY;
}