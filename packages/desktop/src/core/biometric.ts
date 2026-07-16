/**
 * Biometric unlock (Touch ID on macOS, Windows Hello on Windows).
 *
 * After a successful password unlock the user may opt in: we wrap a copy of
 * the derived MASTER KEY (never the password) with the OS keystore (Electron
 * `safeStorage`, backed by the Keychain / DPAPI) and persist that ciphertext
 * together with the unlock context (salt + account) it belongs to. A later
 * launch prompts for biometrics; only on success is the key unwrapped and fed
 * to `VaultApp.unlockWithKey()`.
 *
 * Storing the wrapped key instead of the password means: no password material
 * at rest in any form, and biometric unlock skips the Argon2id run entirely.
 * Biometrics gate access to the wrapped key — the vault blob itself stays
 * AES-256-GCM under that key, so a stolen wrapped blob without the OS
 * keystore (or a stolen vault without the key) is useless.
 *
 * This module is platform-agnostic: the `SecureEnclave` and token storage are
 * injected, so the logic is fully unit-testable without Electron.
 */

export interface SecureEnclave {
  /** Is a biometric-gated keystore available on this machine right now? */
  isAvailable(): Promise<boolean>;
  /** Prompt the user for Touch ID / Windows Hello. Resolves true if they pass. */
  promptUser(reason: string): Promise<boolean>;
  /** Encrypt with the OS keystore (Keychain / DPAPI). Returns base64. */
  encrypt(plaintext: string): string;
  /** Decrypt keystore ciphertext. Throws if the blob is invalid. */
  decrypt(ciphertextB64: string): string;
}

export interface TokenStore {
  read(): Promise<string | null>;
  write(token: string): Promise<void>;
  clear(): Promise<void>;
}

/** What biometric unlock needs to reopen the right vault with the right key. */
export interface WrappedKey {
  keyB64: string;
  saltB64: string;
  /** Account the key belongs to, or null for the local-only vault. */
  userId: string | null;
}

export class BiometricUnlock {
  constructor(
    private readonly enclave: SecureEnclave,
    private readonly tokens: TokenStore
  ) {}

  /** Whether biometric unlock is offered (hardware present + already enrolled). */
  async isEnrolled(): Promise<boolean> {
    return (await this.enclave.isAvailable()) && (await this.tokens.read()) !== null;
  }

  /** Opt in: wrap a copy of the master key behind the OS keystore. */
  async enroll(key: Buffer, saltB64: string, userId: string | null): Promise<void> {
    if (!(await this.enclave.isAvailable())) {
      throw new Error("biometric keystore unavailable on this device");
    }
    const wrapped: WrappedKey = { keyB64: key.toString("base64"), saltB64, userId };
    await this.tokens.write(this.enclave.encrypt(JSON.stringify(wrapped)));
  }

  /** Opt out / on logout: wipe the wrapped key from the keystore. */
  async unenroll(): Promise<void> {
    await this.tokens.clear();
  }

  /**
   * Prompt for biometrics and, on success, unwrap the master key + its unlock
   * context so the caller can run `VaultApp.unlockWithKey()`. Returns null if
   * not enrolled or the biometric prompt was declined/failed. A wrapped blob
   * that no longer decrypts (keystore reset, tampering) is wiped — the user
   * falls back to the master password and can re-enroll.
   */
  async recoverKey(reason = "Unlock VaultKeep"): Promise<{ key: Buffer; saltB64: string; userId: string | null } | null> {
    const token = await this.tokens.read();
    if (!token || !(await this.enclave.isAvailable())) return null;
    const passed = await this.enclave.promptUser(reason);
    if (!passed) return null;
    try {
      const wrapped = JSON.parse(this.enclave.decrypt(token)) as WrappedKey;
      const key = Buffer.from(wrapped.keyB64, "base64");
      if (key.length !== 32) throw new Error("wrapped key malformed");
      return { key, saltB64: wrapped.saltB64, userId: wrapped.userId };
    } catch {
      await this.tokens.clear(); // stale/corrupt enrollment — password fallback
      return null;
    }
  }
}
