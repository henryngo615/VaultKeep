import type { Credential } from "./matcher.js";

/**
 * The unlocked-session cache. Decrypted credentials live ONLY in the backing
 * store the background worker provides — chrome.storage.session in the real
 * extension (memory-only, wiped when the browser closes, never written to
 * disk) — with an expiry timestamp enforced on every read (auto-lock).
 *
 * The master KEY is never stored here or anywhere else: the unlock flow zeroes
 * it as soon as the vault is decrypted. Locking clears the credentials.
 */

export interface SessionData {
  credentials: Credential[];
  expiresAt: number;
}

/** Async key-value store; chrome.storage.session in production, Map in tests. */
export interface SessionBackend {
  get(): Promise<SessionData | null>;
  set(data: SessionData): Promise<void>;
  clear(): Promise<void>;
}

export class InMemorySessionBackend implements SessionBackend {
  private data: SessionData | null = null;
  async get() {
    return this.data;
  }
  async set(data: SessionData) {
    this.data = data;
  }
  async clear() {
    this.data = null;
  }
}

export const DEFAULT_AUTO_LOCK_MS = 5 * 60 * 1000;

export class SessionStore {
  constructor(
    private readonly backend: SessionBackend,
    private readonly autoLockMs: number = DEFAULT_AUTO_LOCK_MS,
    private readonly now: () => number = Date.now
  ) {}

  /** Start an unlocked session; replaces any previous one. */
  async activate(credentials: Credential[]): Promise<void> {
    await this.backend.set({ credentials, expiresAt: this.now() + this.autoLockMs });
  }

  /**
   * The decrypted credentials, or null when locked. An expired session is
   * cleared on read — auto-lock holds even if no timer ever fired (MV3
   * service workers restart at will).
   */
  async credentials(): Promise<Credential[] | null> {
    const data = await this.backend.get();
    if (!data) return null;
    if (this.now() > data.expiresAt) {
      await this.backend.clear();
      return null;
    }
    return data.credentials;
  }

  /** Sliding expiry: any successful use keeps the session alive. */
  async touch(): Promise<void> {
    const data = await this.backend.get();
    if (data && this.now() <= data.expiresAt) {
      await this.backend.set({ ...data, expiresAt: this.now() + this.autoLockMs });
    }
  }

  async lock(): Promise<void> {
    await this.backend.clear();
  }

  async status(): Promise<{ unlocked: boolean; count: number; expiresAt: number | null }> {
    const credentials = await this.credentials();
    if (!credentials) return { unlocked: false, count: 0, expiresAt: null };
    const data = await this.backend.get();
    return { unlocked: true, count: credentials.length, expiresAt: data?.expiresAt ?? null };
  }
}
