/**
 * Account storage. Like the vault repository, this is an interface so the auth
 * logic can be unit-tested in-memory and swapped for Prisma/Postgres in prod.
 *
 * Zero-knowledge note: we store the user's KDF salt + params (so any device can
 * re-derive the ENCRYPTION key locally) and a slow hash of an AUTH verifier
 * (which is itself derived from the master password on the client). The server
 * never sees the master password or the encryption key.
 */
export interface AccountRecord {
  id: string;
  email: string;
  // Public KDF parameters — needed by clients to derive the encryption key.
  kdfSalt: string;
  kdfMemoryKiB: number;
  kdfIterations: number;
  kdfParallel: number;
  // Argon2 hash of the client-supplied auth verifier (NOT the password).
  authHash: string;
  createdAt: string;
}

export interface AccountRepository {
  findByEmail(email: string): Promise<AccountRecord | null>;
  findById(id: string): Promise<AccountRecord | null>;
  create(rec: AccountRecord): Promise<void>;
}

export class InMemoryAccountRepository implements AccountRepository {
  private byId = new Map<string, AccountRecord>();
  private byEmail = new Map<string, string>(); // email -> id

  async findByEmail(email: string): Promise<AccountRecord | null> {
    const id = this.byEmail.get(email.toLowerCase());
    return id ? this.byId.get(id) ?? null : null;
  }
  async findById(id: string): Promise<AccountRecord | null> {
    return this.byId.get(id) ?? null;
  }
  async create(rec: AccountRecord): Promise<void> {
    if (this.byEmail.has(rec.email.toLowerCase())) {
      throw new Error("email already registered");
    }
    this.byId.set(rec.id, { ...rec });
    this.byEmail.set(rec.email.toLowerCase(), rec.id);
  }
}
