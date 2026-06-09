/**
 * The on-disk vault is a SINGLE opaque blob. `VaultApp` encrypts its whole
 * state (items + sync metadata) with the master key before it ever reaches the
 * store, so the store itself needs no key and never sees structure: stealing
 * the file yields one indivisible ciphertext. Even the list of which sites you
 * have a login for is hidden.
 */
export interface LocalStore {
  /** The stored ciphertext blob, or null on first run. */
  readRaw(): Promise<string | null>;
  /** Overwrite the stored blob. */
  writeRaw(blob: string): Promise<void>;
}

/** In-memory store for tests and headless runs. */
export class MemoryStore implements LocalStore {
  private blob: string | null = null;
  async readRaw() {
    return this.blob;
  }
  async writeRaw(blob: string) {
    this.blob = blob;
  }
}

/** File-backed store. Pure I/O — no crypto, no key. */
export class FileStore implements LocalStore {
  constructor(
    private readonly path: string,
    private readonly fs: {
      readFile(p: string, e: "utf8"): Promise<string>;
      writeFile(p: string, d: string): Promise<void>;
    }
  ) {}

  async readRaw(): Promise<string | null> {
    try {
      const raw = await this.fs.readFile(this.path, "utf8");
      return raw || null;
    } catch {
      return null; // first run / missing file
    }
  }

  async writeRaw(blob: string): Promise<void> {
    await this.fs.writeFile(this.path, blob);
  }
}
