import { generateSecret, otpauthURI, verifyTOTP } from "./totp.service.js";

/**
 * Per-user TOTP enrollment + verification.
 *
 * Enrollment is two-phase so we never trust an unconfirmed secret:
 *   1. start()   → generate a secret, store it as PENDING, hand the client the
 *                  otpauth:// URI to show as a QR.
 *   2. confirm() → the user types a code from their authenticator; we verify it
 *                  against the pending secret and only then mark it CONFIRMED.
 *
 * After that, verify() gates every login's MFA step.
 *
 * NOTE: TOTP secrets must be verifiable server-side, so unlike vault data they
 * are NOT encrypted to the user's key. In production they should be encrypted
 * at rest with a server-held KMS key — the repository is the place to do that.
 */
export interface MfaRecord {
  userId: string;
  secret: string;
  confirmed: boolean;
}

export interface MfaRepository {
  get(userId: string): Promise<MfaRecord | null>;
  upsert(rec: MfaRecord): Promise<void>;
}

export class InMemoryMfaRepository implements MfaRepository {
  private items = new Map<string, MfaRecord>();
  async get(userId: string) {
    return this.items.get(userId) ?? null;
  }
  async upsert(rec: MfaRecord) {
    this.items.set(rec.userId, { ...rec });
  }
}

export class MfaService {
  constructor(private readonly repo: MfaRepository) {}

  /** Begin enrollment. Returns the secret + otpauth URI for a QR code. */
  async start(userId: string, accountLabel: string): Promise<{ secret: string; otpauthUri: string }> {
    const secret = generateSecret();
    await this.repo.upsert({ userId, secret, confirmed: false });
    return { secret, otpauthUri: otpauthURI(secret, accountLabel) };
  }

  /** Confirm enrollment by verifying a code against the pending secret. */
  async confirm(userId: string, code: string): Promise<boolean> {
    const rec = await this.repo.get(userId);
    if (!rec) return false;
    if (!verifyTOTP(rec.secret, code)) return false;
    await this.repo.upsert({ ...rec, confirmed: true });
    return true;
  }

  async isEnrolled(userId: string): Promise<boolean> {
    return (await this.repo.get(userId))?.confirmed ?? false;
  }

  /** Verify a login-time code against the CONFIRMED secret. */
  async verify(userId: string, code: string): Promise<boolean> {
    const rec = await this.repo.get(userId);
    if (!rec || !rec.confirmed) return false;
    return verifyTOTP(rec.secret, code);
  }
}
