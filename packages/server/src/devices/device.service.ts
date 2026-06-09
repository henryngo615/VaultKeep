import { randomUUID } from "node:crypto";
import { verifyMessage } from "@vaultkeep/crypto";

/**
 * Device lifecycle + the trust rule that makes a stolen password insufficient:
 * the FIRST device on an account is auto-approved (bootstrap), but every
 * subsequent device starts UNAPPROVED and can only be approved by an
 * already-trusted device signing an attestation with its Ed25519 key. The
 * server verifies that signature — it cannot mint approvals itself.
 */
export interface DeviceRecord {
  id: string;
  userId: string;
  name: string;
  platform: string;
  publicKey: string; // X25519
  signingPublicKey: string; // Ed25519
  approved: boolean;
  createdAt: string;
}

export interface DeviceRepository {
  listForUser(userId: string): Promise<DeviceRecord[]>;
  get(userId: string, deviceId: string): Promise<DeviceRecord | null>;
  create(rec: DeviceRecord): Promise<void>;
  setApproved(userId: string, deviceId: string, approved: boolean): Promise<void>;
}

export class InMemoryDeviceRepository implements DeviceRepository {
  private items = new Map<string, DeviceRecord>(); // `${userId}:${id}`
  private key(u: string, d: string) {
    return `${u}:${d}`;
  }
  async listForUser(userId: string) {
    return [...this.items.values()].filter((d) => d.userId === userId);
  }
  async get(userId: string, deviceId: string) {
    return this.items.get(this.key(userId, deviceId)) ?? null;
  }
  async create(rec: DeviceRecord) {
    this.items.set(this.key(rec.userId, rec.id), { ...rec });
  }
  async setApproved(userId: string, deviceId: string, approved: boolean) {
    const k = this.key(userId, deviceId);
    const cur = this.items.get(k);
    if (cur) this.items.set(k, { ...cur, approved });
  }
}

export interface EnrollInput {
  userId: string;
  name: string;
  platform: string;
  publicKey: string;
  signingPublicKey: string;
}

export class DeviceService {
  constructor(private readonly repo: DeviceRepository) {}

  /** Register a device. First device is auto-approved; others start pending. */
  async enroll(input: EnrollInput): Promise<DeviceRecord> {
    const existing = await this.repo.listForUser(input.userId);
    const isFirst = existing.length === 0;
    const rec: DeviceRecord = {
      id: randomUUID(),
      userId: input.userId,
      name: input.name,
      platform: input.platform,
      publicKey: input.publicKey,
      signingPublicKey: input.signingPublicKey,
      approved: isFirst,
      createdAt: new Date().toISOString(),
    };
    await this.repo.create(rec);
    return rec;
  }

  /**
   * Approve a pending device. The request must be signed by an ALREADY-approved
   * device over the canonical message `approve-device:<targetDeviceId>`. The
   * server verifies the Ed25519 signature against that approver's stored key.
   */
  async approve(
    userId: string,
    approverDeviceId: string,
    targetDeviceId: string,
    signatureB64: string
  ): Promise<{ ok: true } | { ok: false; reason: string }> {
    const approver = await this.repo.get(userId, approverDeviceId);
    if (!approver) return { ok: false, reason: "approver not found" };
    if (!approver.approved) return { ok: false, reason: "approver is not trusted" };

    const target = await this.repo.get(userId, targetDeviceId);
    if (!target) return { ok: false, reason: "target device not found" };

    const message = `approve-device:${targetDeviceId}`;
    const valid = verifyMessage(approver.signingPublicKey, message, signatureB64);
    if (!valid) return { ok: false, reason: "invalid approval signature" };

    await this.repo.setApproved(userId, targetDeviceId, true);
    return { ok: true };
  }

  async isApproved(userId: string, deviceId: string): Promise<boolean> {
    const d = await this.repo.get(userId, deviceId);
    return d?.approved ?? false;
  }

  /** Fetch a device record (e.g. to read its signing public key). */
  async get(userId: string, deviceId: string): Promise<DeviceRecord | null> {
    return this.repo.get(userId, deviceId);
  }

  async list(userId: string): Promise<DeviceRecord[]> {
    return this.repo.listForUser(userId);
  }
}
