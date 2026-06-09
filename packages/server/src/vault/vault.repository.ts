/**
 * Storage abstraction for encrypted vault items. The HTTP layer depends on this
 * interface, not on Prisma directly — which lets us unit-test the sync logic
 * with an in-memory implementation and swap in Postgres for production.
 *
 * NOTHING here ever sees plaintext: `ciphertext` is an opaque base64 blob.
 */

export interface StoredItem {
  id: string;
  userId: string;
  ciphertext: string;
  version: number;
  updatedAt: string; // ISO 8601
}

export interface VaultRepository {
  /** All items for a user changed strictly after `since` (ISO), else all. */
  listSince(userId: string, since?: string): Promise<StoredItem[]>;
  /** Current stored item, or null if the server has never seen this id. */
  get(userId: string, id: string): Promise<StoredItem | null>;
  /** Persist (insert or overwrite) an item at an exact version. */
  put(item: StoredItem): Promise<void>;
  /** Remove an item. */
  remove(userId: string, id: string): Promise<void>;
}

/** In-memory repository — used by tests and `npm run dev` without a database. */
export class InMemoryVaultRepository implements VaultRepository {
  private items = new Map<string, StoredItem>(); // key: `${userId}:${id}`

  private key(userId: string, id: string) {
    return `${userId}:${id}`;
  }

  async listSince(userId: string, since?: string): Promise<StoredItem[]> {
    const cutoff = since ? Date.parse(since) : -Infinity;
    return [...this.items.values()].filter(
      (i) => i.userId === userId && Date.parse(i.updatedAt) > cutoff
    );
  }

  async get(userId: string, id: string): Promise<StoredItem | null> {
    return this.items.get(this.key(userId, id)) ?? null;
  }

  async put(item: StoredItem): Promise<void> {
    this.items.set(this.key(item.userId, item.id), { ...item });
  }

  async remove(userId: string, id: string): Promise<void> {
    this.items.delete(this.key(userId, id));
  }
}
