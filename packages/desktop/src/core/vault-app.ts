import { randomUUID } from "node:crypto";
import {
  deriveMasterKey,
  encrypt,
  decrypt,
  type KdfParams,
} from "@vaultkeep/crypto";
import type { VaultItem } from "@vaultkeep/shared/types.js";
import type { LocalStore } from "./local-store.js";
import type { Transport } from "./sync-client.js";

/** The complete vault state that gets encrypted into one on-disk blob. */
interface PersistedState {
  items: VaultItem[];
  meta: Array<{ id: string; version: number; dirty: boolean }>;
}

/**
 * The desktop app's controller. It is the only place that holds the decrypted
 * master key and the in-memory plaintext items. Everything it persists (locally
 * or to the server) is ciphertext.
 *
 * Lifecycle: construct -> unlock(masterPassword) -> use -> lock().
 */
export class VaultApp {
  private key: Buffer | null = null;
  private items = new Map<string, VaultItem>();
  private meta = new Map<string, { version: number; dirty: boolean }>();

  constructor(
    private readonly saltB64: string,
    private readonly store: LocalStore,
    private readonly transport: Transport | null,
    private readonly kdf?: KdfParams
  ) {}

  get isUnlocked(): boolean {
    return this.key !== null;
  }

  /** Derive the master key and decrypt the local vault into memory. */
  async unlock(masterPassword: string): Promise<void> {
    const key = await deriveMasterKey(masterPassword, this.saltB64, this.kdf);
    const raw = await this.store.readRaw();
    if (raw) {
      // A wrong password makes decrypt() throw (GCM auth tag) -> reject unlock.
      const state = JSON.parse(decrypt(key, raw)) as PersistedState;
      for (const item of state.items) this.items.set(item.id, item);
      for (const m of state.meta)
        this.meta.set(m.id, { version: m.version, dirty: m.dirty });
    }
    this.key = key;
  }

  /** Wipe the key and plaintext from memory. */
  lock(): void {
    this.key?.fill(0);
    this.key = null;
    this.items.clear();
    this.meta.clear();
  }

  list(): VaultItem[] {
    this.assertUnlocked();
    return [...this.items.values()].sort((a, b) =>
      a.title.localeCompare(b.title)
    );
  }

  get(id: string): VaultItem | undefined {
    this.assertUnlocked();
    return this.items.get(id);
  }

  /** Create a new item, persist it encrypted locally, mark for sync. */
  async add(
    partial: Omit<VaultItem, "id" | "createdAt" | "updatedAt" | "tags" | "fields" | "favorite"> &
      Partial<Pick<VaultItem, "tags" | "fields" | "favorite">>
  ): Promise<VaultItem> {
    this.assertUnlocked();
    const now = new Date().toISOString();
    const item: VaultItem = {
      id: randomUUID(),
      tags: [],
      fields: {},
      favorite: false,
      ...partial,
      createdAt: now,
      updatedAt: now,
    };
    this.items.set(item.id, item);
    this.meta.set(item.id, { version: 0, dirty: true });
    await this.persist();
    return item;
  }

  /** Edit an existing item. */
  async update(id: string, patch: Partial<VaultItem>): Promise<VaultItem> {
    this.assertUnlocked();
    const cur = this.items.get(id);
    if (!cur) throw new Error(`no item ${id}`);
    const next = { ...cur, ...patch, id, updatedAt: new Date().toISOString() };
    this.items.set(id, next);
    const m = this.meta.get(id)!;
    this.meta.set(id, { ...m, dirty: true });
    await this.persist();
    return next;
  }

  /**
   * Two-way sync: push every dirty item, then pull remote changes and merge.
   * Conflicts surface the server's newer copy (last-writer-by-version wins;
   * a real UI would prompt). Returns a small summary for the UI.
   */
  async sync(): Promise<{ pushed: number; pulled: number; conflicts: number }> {
    this.assertUnlocked();
    if (!this.transport) throw new Error("offline: no transport configured");
    let pushed = 0,
      pulled = 0,
      conflicts = 0;

    // 1. Push local edits.
    for (const [id, m] of this.meta) {
      if (!m.dirty) continue;
      const item = this.items.get(id)!;
      const blob = encrypt(this.key!, JSON.stringify(item));
      const base = m.version === 0 ? null : m.version;
      const out = await this.transport.push(id, blob, base);
      if (out.status === "ok") {
        this.meta.set(id, { version: out.version, dirty: false });
        pushed++;
      } else {
        conflicts++;
        if (out.server) {
          // Take the server's newer copy.
          const remote = JSON.parse(decrypt(this.key!, out.server.ciphertext)) as VaultItem;
          this.items.set(id, remote);
          this.meta.set(id, { version: out.server.version, dirty: false });
        }
      }
    }

    // 2. Pull remote changes we don't have (or that are newer).
    const remote = await this.transport.pull();
    for (const r of remote) {
      const known = this.meta.get(r.id);
      if (!known || r.version > known.version) {
        const item = JSON.parse(decrypt(this.key!, r.ciphertext)) as VaultItem;
        this.items.set(r.id, item);
        this.meta.set(r.id, { version: r.version, dirty: false });
        pulled++;
      }
    }

    await this.persist();
    return { pushed, pulled, conflicts };
  }

  // --- internals ------------------------------------------------------------

  private async persist(): Promise<void> {
    const key = this.requireKey();
    const state: PersistedState = {
      items: [...this.items.values()],
      meta: [...this.meta.entries()].map(([id, m]) => ({ id, ...m })),
    };
    // The ENTIRE state is encrypted as one blob — ids and metadata included.
    await this.store.writeRaw(encrypt(key, JSON.stringify(state)));
  }

  /** Returns the live key or throws — the single unlock check used everywhere. */
  private requireKey(): Buffer {
    if (!this.key) throw new Error("vault is locked");
    return this.key;
  }

  private assertUnlocked(): void {
    this.requireKey();
  }
}
