// VaultKeep crypto core — the zero-knowledge foundation shared by every client.
export * from "./kdf.js";
export * from "./vault.js";
export * from "./generator.js";
export * from "./devicekeys.js";

import { deriveMasterKey, generateSalt, type KdfParams } from "./kdf.js";
import { encrypt, decrypt } from "./vault.js";

/**
 * High-level convenience: unlock a vault and return a key, plus bound
 * encrypt/decrypt helpers. This is what a client calls right after the user
 * types their master password.
 */
export async function unlockVault(
  masterPassword: string,
  saltB64: string,
  params?: KdfParams
) {
  const key = await deriveMasterKey(masterPassword, saltB64, params);
  return {
    encrypt: (plaintext: string) => encrypt(key, plaintext),
    decrypt: (blob: string) => decrypt(key, blob),
    /** Zero the key out of memory when locking. */
    lock: () => key.fill(0),
  };
}

export { generateSalt };
