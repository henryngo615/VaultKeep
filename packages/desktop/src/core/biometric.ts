/**
 * Biometric unlock (Touch ID on macOS, Windows Hello on Windows).
 *
 * The master password is NEVER stored in plaintext. After a successful
 * password unlock, the user may opt in: we encrypt the master password with the
 * OS secure enclave (Electron `safeStorage`, backed by the Keychain / DPAPI)
 * and persist that ciphertext. A later launch prompts for biometrics; only on
 * success do we decrypt it and feed it back into the normal unlock path.
 *
 * The KDF still runs every unlock — biometrics gate access to the password,
 * they don't replace the zero-knowledge key derivation.
 *
 * This module is platform-agnostic: the `SecureEnclave` and token storage are
 * injected, so the logic is fully unit-testable without Electron.
 */

export interface SecureEnclave {
  /** Is hardware-backed encryption available on this machine right now? */
  isAvailable(): boolean;
  /** Prompt the user for Touch ID / Hello. Resolves true if they pass. */
  promptUser(reason: string): Promise<boolean>;
  /** Encrypt with the OS enclave (Keychain / DPAPI). Returns base64. */
  encrypt(plaintext: string): string;
  /** Decrypt enclave ciphertext. Throws if the blob is invalid. */
  decrypt(ciphertextB64: string): string;
}

export interface TokenStore {
  read(): Promise<string | null>;
  write(token: string): Promise<void>;
  clear(): Promise<void>;
}

export class BiometricUnlock {
  constructor(
    private readonly enclave: SecureEnclave,
    private readonly tokens: TokenStore
  ) {}

  /** Whether biometric unlock is offered (hardware present + already enrolled). */
  async isEnrolled(): Promise<boolean> {
    return this.enclave.isAvailable() && (await this.tokens.read()) !== null;
  }

  /** Opt in: remember the master password behind the secure enclave. */
  async enroll(masterPassword: string): Promise<void> {
    if (!this.enclave.isAvailable()) {
      throw new Error("secure enclave unavailable on this device");
    }
    await this.tokens.write(this.enclave.encrypt(masterPassword));
  }

  /** Opt out / on logout: forget the stored credential. */
  async unenroll(): Promise<void> {
    await this.tokens.clear();
  }

  /**
   * Prompt for biometrics and, on success, recover the master password so the
   * caller can run the normal `VaultApp.unlock(password)`. Returns null if not
   * enrolled or the biometric prompt was declined/failed.
   */
  async recoverPassword(reason = "Unlock VaultKeep"): Promise<string | null> {
    const token = await this.tokens.read();
    if (!token || !this.enclave.isAvailable()) return null;
    const passed = await this.enclave.promptUser(reason);
    if (!passed) return null;
    return this.enclave.decrypt(token);
  }
}
