/**
 * Production storage adapters: the same repository interfaces the tested
 * in-memory versions implement, backed by Prisma/Postgres (schema in
 * ../../prisma/schema.prisma).
 *
 * These are intentionally thin — all logic lives in the tested services; these
 * just translate to/from the database. They are typed against a minimal subset
 * of the PrismaClient so this file compiles without generating the client
 * (run `prisma generate` in deployment). Swap the in-memory repos for these in
 * main.ts when DATABASE_URL is set.
 */
import type { VaultRepository, StoredItem } from "../vault/vault.repository.js";
import type { AccountRepository, AccountRecord } from "../auth/account.repository.js";
import type { DeviceRepository, DeviceRecord } from "../devices/device.service.js";
import type { MfaRepository, MfaRecord } from "../mfa/mfa.service.js";
import type { PasskeyRepository, PasskeyRecord } from "../auth/passkey.service.js";
import type {
  RecoveryRepository, RecoveryRecord, EmergencyContactRecord,
} from "../recovery/recovery.service.js";

// Minimal structural type for the generated PrismaClient we depend on.
interface PrismaLike {
  vaultItem: any;
  user: any;
  device: any;
  mfaMethod: any;
  passkeyCredential: any;
  recoveryKey: any;
  emergencyContact: any;
}

export class PrismaVaultRepository implements VaultRepository {
  constructor(private readonly db: PrismaLike) {}

  async listSince(userId: string, since?: string): Promise<StoredItem[]> {
    const rows = await this.db.vaultItem.findMany({
      where: { userId, ...(since ? { updatedAt: { gt: new Date(since) } } : {}) },
    });
    return rows.map(toStoredItem);
  }

  async get(userId: string, id: string): Promise<StoredItem | null> {
    const row = await this.db.vaultItem.findFirst({ where: { id, userId } });
    return row ? toStoredItem(row) : null;
  }

  async put(item: StoredItem): Promise<void> {
    // Composite key: item ids are only unique per user, so scoping the upsert
    // to (userId, id) makes cross-tenant overwrites impossible.
    await this.db.vaultItem.upsert({
      where: { userId_id: { userId: item.userId, id: item.id } },
      create: {
        id: item.id,
        userId: item.userId,
        ciphertext: item.ciphertext,
        version: item.version,
      },
      update: { ciphertext: item.ciphertext, version: item.version },
    });
  }

  async remove(userId: string, id: string): Promise<void> {
    await this.db.vaultItem.deleteMany({ where: { id, userId } });
  }
}

export class PrismaAccountRepository implements AccountRepository {
  constructor(private readonly db: PrismaLike) {}

  async findByEmail(email: string): Promise<AccountRecord | null> {
    const row = await this.db.user.findUnique({ where: { email: email.toLowerCase() } });
    return row ? toAccount(row) : null;
  }
  async findById(id: string): Promise<AccountRecord | null> {
    const row = await this.db.user.findUnique({ where: { id } });
    return row ? toAccount(row) : null;
  }
  async create(rec: AccountRecord): Promise<void> {
    try {
      await this.db.user.create({
        data: {
          id: rec.id,
          email: rec.email.toLowerCase(),
          kdfSalt: rec.kdfSalt,
          kdfMemoryKiB: rec.kdfMemoryKiB,
          kdfIterations: rec.kdfIterations,
          kdfParallel: rec.kdfParallel,
          authHash: rec.authHash,
        },
      });
    } catch (e: any) {
      // P2002 = unique violation on email; keep the in-memory repo's contract.
      if (e?.code === "P2002") throw new Error("email already registered");
      throw e;
    }
  }
  async updateAuthHash(id: string, authHash: string): Promise<void> {
    await this.db.user.update({ where: { id }, data: { authHash } });
  }
}

export class PrismaDeviceRepository implements DeviceRepository {
  constructor(private readonly db: PrismaLike) {}

  async listForUser(userId: string): Promise<DeviceRecord[]> {
    return (await this.db.device.findMany({ where: { userId } })).map(toDevice);
  }
  async get(userId: string, deviceId: string): Promise<DeviceRecord | null> {
    const row = await this.db.device.findFirst({ where: { id: deviceId, userId } });
    return row ? toDevice(row) : null;
  }
  async create(rec: DeviceRecord): Promise<void> {
    await this.db.device.create({ data: { ...rec, createdAt: new Date(rec.createdAt) } });
  }
  async setApproved(userId: string, deviceId: string, approved: boolean): Promise<void> {
    await this.db.device.updateMany({ where: { id: deviceId, userId }, data: { approved } });
  }
}

export class PrismaMfaRepository implements MfaRepository {
  constructor(private readonly db: PrismaLike) {}

  async get(userId: string): Promise<MfaRecord | null> {
    const row = await this.db.mfaMethod.findUnique({
      where: { userId_kind: { userId, kind: "totp" } },
    });
    return row ? { userId: row.userId, secret: row.secret, confirmed: row.confirmed } : null;
  }

  async upsert(rec: MfaRecord): Promise<void> {
    await this.db.mfaMethod.upsert({
      where: { userId_kind: { userId: rec.userId, kind: "totp" } },
      create: { userId: rec.userId, kind: "totp", secret: rec.secret, confirmed: rec.confirmed },
      update: { secret: rec.secret, confirmed: rec.confirmed },
    });
  }
}

export class PrismaPasskeyRepository implements PasskeyRepository {
  constructor(private readonly db: PrismaLike) {}

  async listForUser(userId: string): Promise<PasskeyRecord[]> {
    return (await this.db.passkeyCredential.findMany({ where: { userId } })).map(toPasskey);
  }
  async get(credentialId: string): Promise<PasskeyRecord | null> {
    const row = await this.db.passkeyCredential.findUnique({ where: { credentialId } });
    return row ? toPasskey(row) : null;
  }
  async create(rec: PasskeyRecord): Promise<void> {
    await this.db.passkeyCredential.create({
      data: { ...rec, createdAt: new Date(rec.createdAt) },
    });
  }
  async updateSignCount(credentialId: string, signCount: number): Promise<void> {
    await this.db.passkeyCredential.update({ where: { credentialId }, data: { signCount } });
  }
}

export class PrismaRecoveryRepository implements RecoveryRepository {
  constructor(private readonly db: PrismaLike) {}

  async getRecovery(userId: string): Promise<RecoveryRecord | null> {
    const row = await this.db.recoveryKey.findUnique({ where: { userId } });
    return row
      ? {
          userId: row.userId,
          verifierHash: row.verifierHash,
          wrappedKey: row.wrappedKey,
          createdAt: toIso(row.createdAt),
        }
      : null;
  }
  async upsertRecovery(rec: RecoveryRecord): Promise<void> {
    const data = {
      verifierHash: rec.verifierHash,
      wrappedKey: rec.wrappedKey,
      createdAt: new Date(rec.createdAt),
    };
    await this.db.recoveryKey.upsert({
      where: { userId: rec.userId },
      create: { userId: rec.userId, ...data },
      update: data,
    });
  }
  async listContacts(userId: string): Promise<EmergencyContactRecord[]> {
    return (await this.db.emergencyContact.findMany({ where: { userId } })).map(toContact);
  }
  async getContact(id: string): Promise<EmergencyContactRecord | null> {
    const row = await this.db.emergencyContact.findUnique({ where: { id } });
    return row ? toContact(row) : null;
  }
  async createContact(rec: EmergencyContactRecord): Promise<void> {
    await this.db.emergencyContact.create({
      data: {
        ...rec,
        unlockAt: rec.unlockAt ? new Date(rec.unlockAt) : null,
        createdAt: new Date(rec.createdAt),
      },
    });
  }
  async updateContact(rec: EmergencyContactRecord): Promise<void> {
    await this.db.emergencyContact.update({
      where: { id: rec.id },
      data: { state: rec.state, unlockAt: rec.unlockAt ? new Date(rec.unlockAt) : null },
    });
  }
}

// --- row -> domain mappers --------------------------------------------------

function toContact(r: any): EmergencyContactRecord {
  return {
    id: r.id,
    userId: r.userId,
    contactEmail: r.contactEmail,
    contactSigningPublicKey: r.contactSigningPublicKey,
    ephemeralPublicKey: r.ephemeralPublicKey,
    wrappedKey: r.wrappedKey,
    state: r.state,
    unlockAt: r.unlockAt ? toIso(r.unlockAt) : null,
    createdAt: toIso(r.createdAt),
  };
}

function toIso(d: any): string {
  return (d instanceof Date ? d : new Date(d)).toISOString();
}

function toStoredItem(r: any): StoredItem {
  return {
    id: r.id,
    userId: r.userId,
    ciphertext: r.ciphertext,
    version: r.version,
    updatedAt: (r.updatedAt instanceof Date ? r.updatedAt : new Date(r.updatedAt)).toISOString(),
  };
}
function toAccount(r: any): AccountRecord {
  return {
    id: r.id,
    email: r.email,
    kdfSalt: r.kdfSalt,
    kdfMemoryKiB: r.kdfMemoryKiB,
    kdfIterations: r.kdfIterations,
    kdfParallel: r.kdfParallel,
    authHash: r.authHash,
    createdAt: (r.createdAt instanceof Date ? r.createdAt : new Date(r.createdAt)).toISOString(),
  };
}
function toPasskey(r: any): PasskeyRecord {
  return {
    credentialId: r.credentialId,
    userId: r.userId,
    publicKeyJwk: r.publicKeyJwk,
    alg: r.alg,
    signCount: r.signCount,
    name: r.name,
    createdAt: (r.createdAt instanceof Date ? r.createdAt : new Date(r.createdAt)).toISOString(),
  };
}
function toDevice(r: any): DeviceRecord {
  return {
    id: r.id,
    userId: r.userId,
    name: r.name,
    platform: r.platform,
    publicKey: r.publicKey,
    signingPublicKey: r.signingPublicKey,
    approved: r.approved,
    createdAt: (r.createdAt instanceof Date ? r.createdAt : new Date(r.createdAt)).toISOString(),
  };
}
