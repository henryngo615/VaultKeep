// ============================================================================
// VaultKeep — shared types across all clients and the server
// ============================================================================

/** Categories of items a vault can hold. */
export type ItemType =
  | "login"
  | "passkey"
  | "secureNote"
  | "creditCard"
  | "bankAccount"
  | "recoveryCodes"
  | "softwareLicense"
  | "identityDocument"
  | "sshKey"
  | "apiKey";

/**
 * A decrypted vault item. This shape exists ONLY in client memory after the
 * vault has been unlocked. It is never sent to the server in this form.
 */
export interface VaultItem {
  id: string; // uuid v4
  type: ItemType;
  title: string;
  username?: string;
  password?: string; // plaintext only in memory
  url?: string;
  notes?: string;
  tags: string[];
  /** Type-specific structured fields (card number, ssh key body, etc.). */
  fields: Record<string, string>;
  favorite: boolean;
  createdAt: string; // ISO 8601
  updatedAt: string; // ISO 8601
}

/**
 * What the client actually uploads. The server only ever sees this — an opaque
 * ciphertext blob plus the metadata it needs to route and version it.
 */
export interface EncryptedVaultItem {
  id: string;
  /** base64( nonce || ciphertext || authTag ) produced by AES-256-GCM. */
  ciphertext: string;
  /** Monotonic version for conflict resolution during sync. */
  version: number;
  updatedAt: string;
}

/** A registered device. Private keys never leave the device. */
export interface Device {
  id: string;
  name: string; // "Henry's iPhone"
  platform: "ios" | "android" | "macos" | "windows" | "linux" | "extension";
  publicKey: string; // base64 X25519 public key
  signingPublicKey: string; // base64 Ed25519 public key
  approved: boolean;
  createdAt: string;
  lastSeenAt: string;
}

export type MfaMethod =
  | { kind: "totp"; label: string }
  | { kind: "webauthn"; credentialId: string; label: string }
  | { kind: "sms"; phoneE164: string }; // recovery only — never primary

export interface SecurityEvent {
  id: string;
  type:
    | "newLogin"
    | "newDevice"
    | "vaultExported"
    | "mfaDisabled"
    | "passwordChanged";
  deviceId?: string;
  createdAt: string;
}
