import { argon2id } from "hash-wasm";

/**
 * Browser-side crypto for the extension — byte-compatible with
 * @vaultkeep/crypto so one vault decrypts everywhere:
 *
 *   key      = Argon2id(masterPassword, salt)                  (hash-wasm)
 *   verifier = HMAC-SHA256(key, "vaultkeep-auth-verifier:"+pw) (WebCrypto)
 *   blob     = base64( nonce(12) ‖ ciphertext ‖ gcmTag(16) )   (WebCrypto)
 *
 * hash-wasm is the same WASM Argon2id the crypto package uses; WebCrypto
 * AES-GCM verifies the auth tag, so a wrong key or tampered blob THROWS
 * rather than returning garbage.
 */

export interface KdfParams {
  memoryKiB: number;
  iterations: number;
  parallelism: number;
}

const NONCE_BYTES = 12;

export async function deriveMasterKey(
  masterPassword: string,
  saltB64: string,
  params: KdfParams
): Promise<Uint8Array> {
  const hash = await argon2id({
    password: masterPassword,
    salt: fromB64(saltB64),
    parallelism: params.parallelism,
    iterations: Math.max(1, params.iterations),
    memorySize: params.memoryKiB,
    hashLength: 32,
    outputType: "binary",
  });
  return new Uint8Array(hash);
}

/** Must match @vaultkeep/crypto's deriveAuthVerifier byte-for-byte. */
export async function deriveAuthVerifier(
  key: Uint8Array,
  masterPassword: string
): Promise<string> {
  const hmacKey = await crypto.subtle.importKey(
    "raw", key as BufferSource, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]
  );
  const mac = await crypto.subtle.sign(
    "HMAC", hmacKey,
    new TextEncoder().encode("vaultkeep-auth-verifier:" + masterPassword)
  );
  return toB64(new Uint8Array(mac));
}

/**
 * Decrypt one vault blob. WebCrypto expects ciphertext‖tag, which is exactly
 * what follows the 12-byte nonce in the shared wire format. Throws on a wrong
 * key or any tampering (GCM auth-tag verification).
 */
export async function decryptBlob(key: Uint8Array, blobB64: string): Promise<string> {
  const blob = fromB64(blobB64);
  if (blob.length < NONCE_BYTES + 16) throw new Error("ciphertext too short / malformed");
  const aesKey = await crypto.subtle.importKey(
    "raw", key as BufferSource, { name: "AES-GCM" }, false, ["decrypt"]
  );
  const plain = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: blob.slice(0, NONCE_BYTES) as BufferSource, tagLength: 128 },
    aesKey,
    blob.slice(NONCE_BYTES) as BufferSource
  );
  return new TextDecoder().decode(plain);
}

/** Wipe key material from memory when locking. */
export function zeroKey(key: Uint8Array): void {
  key.fill(0);
}

export function toB64(bytes: Uint8Array): string {
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin);
}

export function fromB64(s: string): Uint8Array {
  return Uint8Array.from(atob(s), (c) => c.charCodeAt(0));
}
