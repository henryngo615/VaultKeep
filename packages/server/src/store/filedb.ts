import { readFileSync, writeFileSync, mkdirSync } from "node:fs";
import { dirname } from "node:path";
import type { AccountRepository, AccountRecord } from "../auth/account.repository.js";
import type { VaultRepository, StoredItem } from "../vault/vault.repository.js";
import type { DeviceRepository, DeviceRecord } from "../devices/device.service.js";
import type { MfaRepository, MfaRecord } from "../mfa/mfa.service.js";
import type { PasskeyRepository, PasskeyRecord } from "../auth/passkey.service.js";

/**
 * Dead-simple JSON-file persistence so the web vault survives restarts without
 * needing Postgres. Still zero-knowledge: vault items are ciphertext, accounts
 * hold only the Argon2 verifier hash, MFA secrets are the only server-readable
 * secret (as is unavoidable for TOTP). For production, swap in the Prisma
 * adapters — these repos implement the exact same interfaces.
 */
interface DbShape {
  accounts: AccountRecord[];
  devices: DeviceRecord[];
  vault: StoredItem[];
  mfa: MfaRecord[];
  passkeys: PasskeyRecord[];
}

export class FileDb {
  private data: DbShape = { accounts: [], devices: [], vault: [], mfa: [], passkeys: [] };

  constructor(private readonly path: string) {
    try {
      this.data = JSON.parse(readFileSync(path, "utf8"));
      for (const k of ["accounts", "devices", "vault", "mfa", "passkeys"] as const) {
        this.data[k] ??= [];
      }
    } catch {
      mkdirSync(dirname(path), { recursive: true });
      this.save();
    }
  }

  save() {
    writeFileSync(this.path, JSON.stringify(this.data, null, 2));
  }
  get raw() {
    return this.data;
  }
}

export class FileAccountRepository implements AccountRepository {
  constructor(private readonly db: FileDb) {}
  async findByEmail(email: string) {
    return this.db.raw.accounts.find((a) => a.email.toLowerCase() === email.toLowerCase()) ?? null;
  }
  async findById(id: string) {
    return this.db.raw.accounts.find((a) => a.id === id) ?? null;
  }
  async create(rec: AccountRecord) {
    if (await this.findByEmail(rec.email)) throw new Error("email already registered");
    this.db.raw.accounts.push(rec);
    this.db.save();
  }
}

export class FileVaultRepository implements VaultRepository {
  constructor(private readonly db: FileDb) {}
  async listSince(userId: string, since?: string) {
    const cutoff = since ? Date.parse(since) : -Infinity;
    return this.db.raw.vault.filter((i) => i.userId === userId && Date.parse(i.updatedAt) > cutoff);
  }
  async get(userId: string, id: string) {
    return this.db.raw.vault.find((i) => i.userId === userId && i.id === id) ?? null;
  }
  async put(item: StoredItem) {
    const i = this.db.raw.vault.findIndex((x) => x.userId === item.userId && x.id === item.id);
    if (i >= 0) this.db.raw.vault[i] = { ...item };
    else this.db.raw.vault.push({ ...item });
    this.db.save();
  }
  async remove(userId: string, id: string) {
    this.db.raw.vault = this.db.raw.vault.filter((i) => !(i.userId === userId && i.id === id));
    this.db.save();
  }
}

export class FileDeviceRepository implements DeviceRepository {
  constructor(private readonly db: FileDb) {}
  async listForUser(userId: string) {
    return this.db.raw.devices.filter((d) => d.userId === userId);
  }
  async get(userId: string, deviceId: string) {
    return this.db.raw.devices.find((d) => d.userId === userId && d.id === deviceId) ?? null;
  }
  async create(rec: DeviceRecord) {
    this.db.raw.devices.push(rec);
    this.db.save();
  }
  async setApproved(userId: string, deviceId: string, approved: boolean) {
    const d = this.db.raw.devices.find((x) => x.userId === userId && x.id === deviceId);
    if (d) { d.approved = approved; this.db.save(); }
  }
}

export class FilePasskeyRepository implements PasskeyRepository {
  constructor(private readonly db: FileDb) {}
  async listForUser(userId: string) {
    return this.db.raw.passkeys.filter((c) => c.userId === userId);
  }
  async get(credentialId: string) {
    return this.db.raw.passkeys.find((c) => c.credentialId === credentialId) ?? null;
  }
  async create(rec: PasskeyRecord) {
    this.db.raw.passkeys.push({ ...rec });
    this.db.save();
  }
  async updateSignCount(credentialId: string, signCount: number) {
    const c = this.db.raw.passkeys.find((x) => x.credentialId === credentialId);
    if (c) { c.signCount = signCount; this.db.save(); }
  }
}

export class FileMfaRepository implements MfaRepository {
  constructor(private readonly db: FileDb) {}
  async get(userId: string) {
    return this.db.raw.mfa.find((m) => m.userId === userId) ?? null;
  }
  async upsert(rec: MfaRecord) {
    const i = this.db.raw.mfa.findIndex((m) => m.userId === rec.userId);
    if (i >= 0) this.db.raw.mfa[i] = { ...rec };
    else this.db.raw.mfa.push({ ...rec });
    this.db.save();
  }
}
