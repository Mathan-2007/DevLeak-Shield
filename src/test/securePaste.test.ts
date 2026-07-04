/**
 * securePaste.test.ts
 *
 * ASSUMPTIONS:
 * - A function `securePasteTransform(clipboardText, tokenMap, cryptoService, key)`
 *   exists (extract from smartPaste command handler if currently inline).
 * - Token format is `[REDACTED_xxxx]` where xxxx maps to an encrypted payload
 *   held in-memory (tokenMap) for the current session.
 * - If the token isn't recognized (wrong session, tampered, or expired),
 *   paste should fall back to returning the clipboard text unchanged —
 *   never throw, never silently corrupt unrelated text.
 */

import { expect } from "chai";
import { CryptoService } from "./CryptoService";
import { securePasteTransform } from "./securePasteTransform"; // extract if inline

describe("Secure Paste workflow", () => {
  let crypto: CryptoService;
  let key: string;

  beforeEach(() => {
    crypto = new CryptoService();
    key = crypto.generateKey();
  });

  it("restores the original secret when the token matches the current session key", () => {
    const secret = "sk-live-a8f9d7e6b5c4d3e2f1a0";
    const encrypted = crypto.encrypt(secret, key);
    const tokenMap = { "9f3a": encrypted };
    const clipboard = "OPENAI_API_KEY=[REDACTED_9f3a]";

    const result = securePasteTransform(clipboard, tokenMap, crypto, key);
    expect(result).to.equal(`OPENAI_API_KEY=${secret}`);
  });

  it("restores multiple tokens in the same paste independently", () => {
    const secretA = "sk-live-a8f9d7e6b5c4d3e2f1a0";
    const secretB = "root12345";
    const tokenMap = {
      "9f3a": crypto.encrypt(secretA, key),
      "2b71": crypto.encrypt(secretB, key),
    };
    const clipboard = "KEY=[REDACTED_9f3a]\nPASS=[REDACTED_2b71]";

    const result = securePasteTransform(clipboard, tokenMap, crypto, key);
    expect(result).to.equal(`KEY=${secretA}\nPASS=${secretB}`);
  });

  it("falls back to unchanged text when the token id is unknown (different session)", () => {
    const clipboard = "OPENAI_API_KEY=[REDACTED_ffff]"; // not in tokenMap
    const result = securePasteTransform(clipboard, {}, crypto, key);
    expect(result).to.equal(clipboard);
  });

  it("falls back gracefully when decryption fails (wrong key / corrupted payload)", () => {
    const secret = "sk-live-a8f9d7e6b5c4d3e2f1a0";
    const encrypted = crypto.encrypt(secret, key);
    const wrongKey = crypto.generateKey();
    const tokenMap = { "9f3a": encrypted };
    const clipboard = "OPENAI_API_KEY=[REDACTED_9f3a]";

    expect(() => securePasteTransform(clipboard, tokenMap, crypto, wrongKey)).to.not.throw();
    const result = securePasteTransform(clipboard, tokenMap, crypto, wrongKey);
    expect(result).to.equal(clipboard); // must not throw or return garbage
  });

  it("does not alter clipboard text that contains no tokens at all", () => {
    const clipboard = "just a normal line of code, nothing redacted here";
    const result = securePasteTransform(clipboard, {}, crypto, key);
    expect(result).to.equal(clipboard);
  });

  it("does not falsely match text that merely resembles a token format", () => {
    const clipboard = "This is not [REDACTED_XYZ] a real token, just text.";
    const result = securePasteTransform(clipboard, {}, crypto, key);
    expect(result).to.equal(clipboard);
  });
});
