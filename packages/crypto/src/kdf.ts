import { argon2id } from "hash-wasm";
import { randomBytes, createHmac } from "node:crypto";

/**
 * Argon2id parameters. These are the tunable cost factors that stand between an
 * attacker who has stolen an encrypted vault and the master key.
 *
 * We use hash-wasm (pure WASM) so the EXACT same Argon2id runs in Node, Electron,
 * and the browser — which is what lets the desktop app and the web vault share
 * one vault: identical params + salt + password => identical key everywhere.
 */
export interface KdfParams {
  /** Memory cost in KiB. */
  memoryKiB: number;
  /** Number of iterations (time cost). */
  iterations: number;
  /** Degree of parallelism (lanes). */
  parallelism: number;
}

/** Browser-friendly defaults, shared by every client. 64 MiB / t=3 / p=4. */
export const DEFAULT_KDF: KdfParams = {
  memoryKiB: 65536,
  iterations: 3,
  parallelism: 4,
};

/** A fresh 16-byte random salt, base64-encoded. Stored alongside the vault. */
export function generateSalt(): string {
  return randomBytes(16).toString("base64");
}

/**
 * Derive a 256-bit symmetric key from the user's master password using
 * Argon2id. The ONLY thing that turns a human password into the AES key — the
 * server never runs this and never sees its output.
 */
export async function deriveMasterKey(
  masterPassword: string,
  saltB64: string,
  params: KdfParams = DEFAULT_KDF
): Promise<Buffer> {
  const hash = await argon2id({
    password: masterPassword,
    salt: Buffer.from(saltB64, "base64"),
    parallelism: params.parallelism,
    iterations: Math.max(1, params.iterations),
    memorySize: params.memoryKiB,
    hashLength: 32,
    outputType: "binary",
  });
  return Buffer.from(hash);
}

/**
 * Derive the AUTH VERIFIER the client sends at login. One-way function of the
 * encryption key + master password: the server can verify it, but it reveals
 * nothing about the encryption key and is provably distinct from it.
 */
export function deriveAuthVerifier(
  encryptionKey: Buffer,
  masterPassword: string
): string {
  return createHmac("sha256", encryptionKey)
    .update("vaultkeep-auth-verifier:" + masterPassword)
    .digest("base64");
}
