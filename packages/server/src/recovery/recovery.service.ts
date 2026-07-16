import { randomUUID, randomBytes } from "node:crypto";
import { argon2id, argon2Verify } from "hash-wasm";
import { verifyMessage } from "@vaultkeep/crypto";

/**
 * Recovery without server-side decryption ability.
 *
 * Recovery key path: the client keeps the wrap half of its recovery key and
 * sends only (a) an auth verifier — stored as an Argon2 hash — and (b) the
 * master key WRAPPED under the client-only wrap key. Presenting the verifier
 * later returns the wrapped blob; unwrapping happens on the client. The
 * server's whole inventory is one hash + one ciphertext.
 *
 * Emergency-contact path: the owner uploads the master key SEALED to the
 * contact's X25519 public key. A contact's request (Ed25519-signed — the same
 * trust primitive as device approvals) starts a waiting period the server
 * enforces:
 *
 *     enrolled ── request ──▶ pending(unlockAt) ── timer elapses ──▶ releasable
 *                                  │                                    │
 *                             owner denies                          collect
 *                                  ▼                                    ▼
 *                               denied                              released
 *
 * Before unlockAt the sealed blob is NEVER returned; an owner denial is
 * permanent until re-enrollment. Every transition fires a notification hook.
 */

export interface RecoveryRecord {
  userId: string;
  /** Argon2 hash of the recovery auth verifier (never the verifier itself). */
  verifierHash: string;
  /** Master key wrapped under the client-only wrap key — opaque ciphertext. */
  wrappedKey: string;
  createdAt: string;
}

export type EmergencyState = "enrolled" | "pending" | "denied" | "released";

export interface EmergencyContactRecord {
  id: string;
  userId: string;
  contactEmail: string;
  /** Contact's Ed25519 public key — authenticates their requests. */
  contactSigningPublicKey: string;
  /** Ephemeral X25519 public key + master key sealed to the contact. */
  ephemeralPublicKey: string;
  wrappedKey: string;
  state: EmergencyState;
  /** When the waiting period ends (set while pending). */
  unlockAt: string | null;
  createdAt: string;
}

export interface RecoveryRepository {
  getRecovery(userId: string): Promise<RecoveryRecord | null>;
  upsertRecovery(rec: RecoveryRecord): Promise<void>;
  listContacts(userId: string): Promise<EmergencyContactRecord[]>;
  getContact(id: string): Promise<EmergencyContactRecord | null>;
  createContact(rec: EmergencyContactRecord): Promise<void>;
  updateContact(rec: EmergencyContactRecord): Promise<void>;
}

/** Notification hooks — wire to email/push in production; tests observe them. */
export interface RecoveryNotifier {
  emergencyRequested(userId: string, contact: EmergencyContactRecord): void;
  emergencyDenied(userId: string, contact: EmergencyContactRecord): void;
  emergencyReleased(userId: string, contact: EmergencyContactRecord): void;
  recoveryKeyUsed(userId: string): void;
}

export const silentNotifier: RecoveryNotifier = {
  emergencyRequested: () => {},
  emergencyDenied: () => {},
  emergencyReleased: () => {},
  recoveryKeyUsed: () => {},
};

export const DEFAULT_WAIT_MS = 7 * 24 * 60 * 60 * 1000; // 7 days

export class RecoveryService {
  constructor(
    private readonly repo: RecoveryRepository,
    private readonly notifier: RecoveryNotifier = silentNotifier,
    private readonly waitMs: number = DEFAULT_WAIT_MS,
    private readonly now: () => number = Date.now
  ) {}

  // --- recovery key -----------------------------------------------------

  /** Store (or rotate) the wrapped master key + verifier hash. */
  async setup(userId: string, authVerifier: string, wrappedKey: string): Promise<void> {
    if (!authVerifier || authVerifier.length < 16) throw new Error("verifier too weak");
    if (!wrappedKey) throw new Error("wrapped key required");
    await this.repo.upsertRecovery({
      userId,
      verifierHash: await hashSecret(authVerifier),
      wrappedKey,
      createdAt: new Date(this.now()).toISOString(),
    });
  }

  async isConfigured(userId: string): Promise<boolean> {
    return (await this.repo.getRecovery(userId)) !== null;
  }

  /**
   * Present the recovery verifier, get the wrapped blob. The server verifies
   * against the stored hash and returns ciphertext it cannot open. Every
   * successful use fires a notification (the real owner should hear about it).
   */
  async begin(userId: string, authVerifier: string): Promise<{ wrappedKey: string } | null> {
    const rec = await this.repo.getRecovery(userId);
    if (!rec) {
      await hashSecret(authVerifier).catch(() => "");
      return null; // constant-ish time for unknown users
    }
    const ok = await argon2Verify({ password: authVerifier, hash: rec.verifierHash }).catch(() => false);
    if (!ok) return null;
    this.notifier.recoveryKeyUsed(userId);
    return { wrappedKey: rec.wrappedKey };
  }

  // --- emergency contacts -------------------------------------------------

  async addContact(input: {
    userId: string;
    contactEmail: string;
    contactSigningPublicKey: string;
    ephemeralPublicKey: string;
    wrappedKey: string;
  }): Promise<EmergencyContactRecord> {
    if (!input.contactSigningPublicKey || !input.wrappedKey || !input.ephemeralPublicKey) {
      throw new Error("contact key material required");
    }
    const rec: EmergencyContactRecord = {
      id: randomUUID(),
      userId: input.userId,
      contactEmail: input.contactEmail,
      contactSigningPublicKey: input.contactSigningPublicKey,
      ephemeralPublicKey: input.ephemeralPublicKey,
      wrappedKey: input.wrappedKey,
      state: "enrolled",
      unlockAt: null,
      createdAt: new Date(this.now()).toISOString(),
    };
    await this.repo.createContact(rec);
    return rec;
  }

  listContacts(userId: string): Promise<EmergencyContactRecord[]> {
    return this.repo.listContacts(userId);
  }

  /**
   * Contact requests access, proving control of their key by signing
   * `emergency-request:<contactId>`. Starts the waiting period and notifies
   * the owner. Denied contacts cannot re-request (owner must re-enroll them).
   */
  async requestAccess(contactId: string, signatureB64: string): Promise<{ unlockAt: string } | null> {
    const c = await this.repo.getContact(contactId);
    if (!c) return null;
    if (!verifySig(c.contactSigningPublicKey, `emergency-request:${contactId}`, signatureB64)) return null;
    if (c.state === "denied" || c.state === "released") return null;
    if (c.state === "pending") return { unlockAt: c.unlockAt! }; // idempotent

    c.state = "pending";
    c.unlockAt = new Date(this.now() + this.waitMs).toISOString();
    await this.repo.updateContact(c);
    this.notifier.emergencyRequested(c.userId, c);
    return { unlockAt: c.unlockAt };
  }

  /** Owner (authenticated upstream) denies a pending request — permanent. */
  async deny(userId: string, contactId: string): Promise<boolean> {
    const c = await this.repo.getContact(contactId);
    if (!c || c.userId !== userId || c.state !== "pending") return false;
    c.state = "denied";
    c.unlockAt = null;
    await this.repo.updateContact(c);
    this.notifier.emergencyDenied(userId, c);
    return true;
  }

  /**
   * After the waiting period, the contact (again proving key control, over
   * `emergency-collect:<contactId>`) gets the sealed blob. Refused — with the
   * blob never leaving the server — while the timer runs or after a denial.
   */
  async collect(
    contactId: string,
    signatureB64: string
  ): Promise<{ ephemeralPublicKey: string; wrappedKey: string } | { waitUntil: string } | null> {
    const c = await this.repo.getContact(contactId);
    if (!c) return null;
    if (!verifySig(c.contactSigningPublicKey, `emergency-collect:${contactId}`, signatureB64)) return null;
    if (c.state === "denied" || c.state === "enrolled") return null;
    if (c.state === "pending") {
      if (this.now() < Date.parse(c.unlockAt!)) return { waitUntil: c.unlockAt! };
      c.state = "released";
      await this.repo.updateContact(c);
      this.notifier.emergencyReleased(c.userId, c);
    }
    return { ephemeralPublicKey: c.ephemeralPublicKey, wrappedKey: c.wrappedKey };
  }
}

function verifySig(publicKeyB64: string, message: string, signatureB64: string): boolean {
  try {
    return verifyMessage(publicKeyB64, message, signatureB64);
  } catch {
    return false;
  }
}

/** Slow Argon2id hash of a presented secret — mirrors the login verifier. */
async function hashSecret(secret: string): Promise<string> {
  return argon2id({
    password: secret,
    salt: randomBytes(16),
    parallelism: 1,
    iterations: 3,
    memorySize: 19456,
    hashLength: 32,
    outputType: "encoded",
  });
}

export class InMemoryRecoveryRepository implements RecoveryRepository {
  private recoveries = new Map<string, RecoveryRecord>();
  private contacts = new Map<string, EmergencyContactRecord>();

  async getRecovery(userId: string) {
    return this.recoveries.get(userId) ?? null;
  }
  async upsertRecovery(rec: RecoveryRecord) {
    this.recoveries.set(rec.userId, { ...rec });
  }
  async listContacts(userId: string) {
    return [...this.contacts.values()].filter((c) => c.userId === userId);
  }
  async getContact(id: string) {
    return this.contacts.get(id) ?? null;
  }
  async createContact(rec: EmergencyContactRecord) {
    this.contacts.set(rec.id, { ...rec });
  }
  async updateContact(rec: EmergencyContactRecord) {
    this.contacts.set(rec.id, { ...rec });
  }

  /** Test hook: everything the server knows, as one string. */
  dump(): string {
    return JSON.stringify({ r: [...this.recoveries.values()], c: [...this.contacts.values()] });
  }
}
