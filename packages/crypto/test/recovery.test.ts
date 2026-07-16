import { describe, it, expect } from "vitest";
import { randomBytes } from "node:crypto";
import {
  generateRecoveryKey,
  normalizeRecoveryKey,
  deriveRecoveryParts,
  wrapMasterKey,
  unwrapMasterKey,
  wrapKeyForContact,
  unwrapKeyFromContact,
  generateExchangeKeys,
} from "../src/index.js";

const SALT = randomBytes(16).toString("base64");

describe("recovery key", () => {
  it("generates a well-formed, high-entropy key", () => {
    const key = generateRecoveryKey();
    expect(key).toMatch(/^VK(-[0-9A-HJKMNP-TV-Z]{5}){5}$/);
    expect(generateRecoveryKey()).not.toBe(key);
  });

  it("normalization forgives case, separators, and O/0 I/1 misreads", () => {
    expect(normalizeRecoveryKey("vk-abcde 0lo1i")).toBe(normalizeRecoveryKey("VK-ABCDE-01011"));
  });

  it("derives independent auth and wrap halves", () => {
    const parts = deriveRecoveryParts(generateRecoveryKey(), SALT);
    expect(parts.wrapKey.length).toBe(32);
    // The verifier must not reveal the wrap key.
    expect(parts.authVerifier).not.toBe(parts.wrapKey.toString("base64"));
  });

  it("round-trips the master key through the wrapped blob", () => {
    const recoveryKey = generateRecoveryKey();
    const masterKey = randomBytes(32);
    const blob = wrapMasterKey(deriveRecoveryParts(recoveryKey, SALT).wrapKey, masterKey);

    // Later, with only the recovery key (typed sloppily) + salt + blob:
    const reparts = deriveRecoveryParts(recoveryKey.toLowerCase().replace(/-/g, " "), SALT);
    expect(unwrapMasterKey(reparts.wrapKey, blob).equals(masterKey)).toBe(true);
    // The blob leaks nothing recognizable.
    expect(blob).not.toContain(masterKey.toString("base64").slice(0, 16));
  });

  it("a wrong recovery key fails to unwrap (GCM auth tag)", () => {
    const masterKey = randomBytes(32);
    const blob = wrapMasterKey(deriveRecoveryParts(generateRecoveryKey(), SALT).wrapKey, masterKey);
    const wrong = deriveRecoveryParts(generateRecoveryKey(), SALT);
    expect(() => unwrapMasterKey(wrong.wrapKey, blob)).toThrow();
  });
});

describe("emergency-contact seal (X25519)", () => {
  it("only the contact's private key opens the sealed master key", () => {
    const contact = generateExchangeKeys();
    const masterKey = randomBytes(32);
    const sealed = wrapKeyForContact(masterKey, contact.publicKey);

    expect(unwrapKeyFromContact(contact.privateKey, sealed).equals(masterKey)).toBe(true);

    const stranger = generateExchangeKeys();
    expect(() => unwrapKeyFromContact(stranger.privateKey, sealed)).toThrow();
  });

  it("the sealed blob + ephemeral public key alone reveal nothing", () => {
    const contact = generateExchangeKeys();
    const masterKey = randomBytes(32);
    const sealed = wrapKeyForContact(masterKey, contact.publicKey);
    // Everything the server stores:
    const serverView = JSON.stringify(sealed);
    expect(serverView).not.toContain(masterKey.toString("base64"));
  });
});
