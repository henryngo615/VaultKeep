import {
  generateKeyPairSync,
  sign,
  verify,
  diffieHellman,
  createPublicKey,
  createPrivateKey,
  KeyObject,
} from "node:crypto";

/**
 * Per-device key material. Each device generates these locally and ONLY ever
 * exports the public halves. The private keys never touch the network — this is
 * what lets a trusted device approve a new one without the server being able to
 * impersonate either.
 */

export interface DeviceKeyPair {
  publicKey: string; // base64 SPKI
  privateKey: string; // base64 PKCS8 — stays on device
}

/** X25519 keypair for ECDH (sharing the vault key to a new device). */
export function generateExchangeKeys(): DeviceKeyPair {
  const { publicKey, privateKey } = generateKeyPairSync("x25519");
  return exportPair(publicKey, privateKey);
}

/** Ed25519 keypair for signing device-approval attestations. */
export function generateSigningKeys(): DeviceKeyPair {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  return exportPair(publicKey, privateKey);
}

/** Derive a shared secret between our private key and a peer's public key. */
export function deriveSharedSecret(
  ourPrivateB64: string,
  theirPublicB64: string
): Buffer {
  return diffieHellman({
    privateKey: importPrivate(ourPrivateB64),
    publicKey: importPublic(theirPublicB64),
  });
}

export function signMessage(privateB64: string, message: string): string {
  return sign(null, Buffer.from(message), importPrivate(privateB64)).toString(
    "base64"
  );
}

export function verifyMessage(
  publicB64: string,
  message: string,
  signatureB64: string
): boolean {
  return verify(
    null,
    Buffer.from(message),
    importPublic(publicB64),
    Buffer.from(signatureB64, "base64")
  );
}

// --- internal helpers -------------------------------------------------------

function exportPair(pub: KeyObject, priv: KeyObject): DeviceKeyPair {
  return {
    publicKey: pub.export({ type: "spki", format: "der" }).toString("base64"),
    privateKey: priv
      .export({ type: "pkcs8", format: "der" })
      .toString("base64"),
  };
}
function importPublic(b64: string): KeyObject {
  return createPublicKey({
    key: Buffer.from(b64, "base64"),
    type: "spki",
    format: "der",
  });
}
function importPrivate(b64: string): KeyObject {
  return createPrivateKey({
    key: Buffer.from(b64, "base64"),
    type: "pkcs8",
    format: "der",
  });
}
