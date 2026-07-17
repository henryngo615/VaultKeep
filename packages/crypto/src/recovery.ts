import { hkdfSync, randomBytes } from "node:crypto";
import { encrypt, decrypt } from "./vault.js";
import { deriveSharedSecret, generateExchangeKeys } from "./devicekeys.js";

/**
 * Recovery kit — the escape hatch for a forgotten master password that keeps
 * the server blind.
 *
 * At setup the CLIENT generates a high-entropy recovery key and splits it,
 * via HKDF with independent info labels, into:
 *
 *   authVerifier — sent to the server, which stores only an Argon2 hash of it
 *                  (same pattern as login: the server can check it, not use it)
 *   wrapKey      — NEVER leaves the client; AES-256-GCM-wraps the master key
 *
 * The server stores the wrapped blob. Holding blob + verifier hash, it still
 * cannot derive wrapKey (HKDF is one-way and the two outputs are independent),
 * so it can never decrypt. Recovery = present the verifier, get the blob back,
 * unwrap locally.
 *
 * Emergency access wraps the master key TO A CONTACT's X25519 public key
 * (ephemeral-key ECDH, like an age/NaCl "seal"): only the contact's private
 * key — which the server never sees — can unwrap what the server releases
 * after the waiting period.
 */

const GROUPS = 5;
const GROUP_LEN = 5;
// Crockford base32: no I/L/O/U — unambiguous to read off paper.
const ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";

/** e.g. VK-1A2B3-C4D5E-F6G7H-J8K9M-NP0QR (25 chars ≈ 125 bits of entropy). */
export function generateRecoveryKey(): string {
  const groups: string[] = [];
  for (let g = 0; g < GROUPS; g++) {
    let s = "";
    for (let i = 0; i < GROUP_LEN; i++) {
      // Rejection sampling for an unbiased draw from the 32-char alphabet.
      let b: number;
      do {
        b = randomBytes(1)[0];
      } while (b >= 224); // 224 = 7 * 32
      s += ALPHABET[b % 32];
    }
    groups.push(s);
  }
  return "VK-" + groups.join("-");
}

/** Forgiving normalization: case, separators, and the easy misreadings. */
export function normalizeRecoveryKey(input: string): string {
  return input
    .toUpperCase()
    .replace(/[^0-9A-Z]/g, "")
    .replace(/^VK/, "")
    .replace(/[IL]/g, "1")
    .replace(/O/g, "0");
}

export interface RecoveryParts {
  /** Present to the server; it stores/checks a hash, nothing more. */
  authVerifier: string;
  /** Client-only: unwraps the master key. */
  wrapKey: Buffer;
}

/** Split the recovery key into its two independent halves. */
export function deriveRecoveryParts(recoveryKey: string, saltB64: string): RecoveryParts {
  const ikm = Buffer.from(normalizeRecoveryKey(recoveryKey), "utf8");
  const salt = Buffer.from(saltB64, "base64");
  const auth = hkdfSync("sha256", ikm, salt, "vaultkeep-recovery-auth", 32);
  const wrap = hkdfSync("sha256", ikm, salt, "vaultkeep-recovery-wrap", 32);
  return {
    authVerifier: Buffer.from(auth).toString("base64"),
    wrapKey: Buffer.from(wrap),
  };
}

/** AES-256-GCM-wrap the master key for server-side storage of the blob. */
export function wrapMasterKey(wrapKey: Buffer, masterKey: Buffer): string {
  return encrypt(wrapKey, masterKey.toString("base64"));
}

/** Unwrap; throws (GCM auth tag) on a wrong recovery key or tampered blob. */
export function unwrapMasterKey(wrapKey: Buffer, blobB64: string): Buffer {
  return Buffer.from(decrypt(wrapKey, blobB64), "base64");
}

export interface ContactWrappedKey {
  /** Ephemeral X25519 public key used for this seal (not secret). */
  ephemeralPublicKey: string;
  /** The master key, decryptable only with the contact's private key. */
  blob: string;
}

/** Seal the master key to an emergency contact's X25519 public key. */
export function wrapKeyForContact(masterKey: Buffer, contactPublicB64: string): ContactWrappedKey {
  const ephemeral = generateExchangeKeys();
  const wrapKey = contactWrapKey(ephemeral.privateKey, contactPublicB64);
  return {
    ephemeralPublicKey: ephemeral.publicKey,
    blob: encrypt(wrapKey, masterKey.toString("base64")),
  };
}

/** Contact side: unseal with their private key + the stored ephemeral public. */
export function unwrapKeyFromContact(
  contactPrivateB64: string,
  wrapped: ContactWrappedKey
): Buffer {
  const wrapKey = contactWrapKey(contactPrivateB64, wrapped.ephemeralPublicKey);
  return Buffer.from(decrypt(wrapKey, wrapped.blob), "base64");
}

function contactWrapKey(privateB64: string, publicB64: string): Buffer {
  const shared = deriveSharedSecret(privateB64, publicB64);
  return Buffer.from(hkdfSync("sha256", shared, Buffer.alloc(0), "vaultkeep-emergency-wrap", 32));
}
