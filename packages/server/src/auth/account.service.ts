import { randomUUID, timingSafeEqual, randomBytes } from "node:crypto";
import { argon2id, argon2Verify } from "hash-wasm";
import type { AccountRepository, AccountRecord } from "./account.repository.js";

/**
 * Account registration + login, zero-knowledge style (the Bitwarden/1Password
 * model). The client derives TWO things from the master password:
 *
 *   encryptionKey = Argon2id(masterPassword, salt)        ← never leaves device
 *   authVerifier  = Argon2id(encryptionKey, masterPassword) ← sent at login only
 *
 * The server stores Argon2id(authVerifier) as `authHash`. So:
 *   - the server can verify a login (does the presented verifier hash match?)
 *   - but can NEVER derive the encryption key or the master password from it.
 *
 * `authVerifier` is opaque to this service — it just treats it as a secret
 * string to hash and compare.
 */

export interface RegisterInput {
  email: string;
  authVerifier: string; // client-derived; server never sees the password
  kdfSalt: string;
  kdfMemoryKiB?: number;
  kdfIterations?: number;
  kdfParallel?: number;
}

export interface PublicKdf {
  kdfSalt: string;
  kdfMemoryKiB: number;
  kdfIterations: number;
  kdfParallel: number;
}

export class AccountService {
  constructor(private readonly repo: AccountRepository) {}

  async register(input: RegisterInput): Promise<{ userId: string }> {
    if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(input.email)) {
      throw new Error("invalid email");
    }
    if (!input.authVerifier || input.authVerifier.length < 16) {
      throw new Error("auth verifier too weak");
    }
    const rec: AccountRecord = {
      id: randomUUID(),
      email: input.email,
      kdfSalt: input.kdfSalt,
      kdfMemoryKiB: input.kdfMemoryKiB ?? 65536,
      kdfIterations: input.kdfIterations ?? 3,
      kdfParallel: input.kdfParallel ?? 4,
      authHash: await hashVerifier(input.authVerifier),
      createdAt: new Date().toISOString(),
    };
    await this.repo.create(rec);
    return { userId: rec.id };
  }

  /** Email for a known user id (e.g. to label a passkey), or null. */
  async emailFor(userId: string): Promise<string | null> {
    return (await this.repo.findById(userId))?.email ?? null;
  }

  /** User id for an email, or null. Callers must not leak this to clients. */
  async idFor(email: string): Promise<string | null> {
    return (await this.repo.findByEmail(email))?.id ?? null;
  }

  /**
   * The public KDF params a client needs BEFORE login, so it can derive the
   * verifier with the same salt. Returns a decoy for unknown emails to avoid
   * leaking which addresses are registered (user-enumeration resistance).
   */
  async kdfParamsFor(email: string): Promise<PublicKdf> {
    const acc = await this.repo.findByEmail(email);
    if (acc) {
      return {
        kdfSalt: acc.kdfSalt,
        kdfMemoryKiB: acc.kdfMemoryKiB,
        kdfIterations: acc.kdfIterations,
        kdfParallel: acc.kdfParallel,
      };
    }
    // Deterministic decoy derived from the email so it's stable per-address.
    return { kdfSalt: decoySalt(email), kdfMemoryKiB: 65536, kdfIterations: 3, kdfParallel: 4 };
  }

  /**
   * Replace the login verifier (recovery / password change). The caller is
   * responsible for having authenticated the request — here that's a verified
   * recovery key. Vault re-encryption is the CLIENT's job: the server only
   * ever swaps one hash for another.
   */
  async resetVerifier(userId: string, newAuthVerifier: string): Promise<void> {
    if (!newAuthVerifier || newAuthVerifier.length < 16) {
      throw new Error("auth verifier too weak");
    }
    await this.repo.updateAuthHash(userId, await hashVerifier(newAuthVerifier));
  }

  /**
   * Verify a login. Returns the userId on success, null on failure. Runs a
   * hash even for unknown users to keep timing roughly constant.
   */
  async verifyLogin(email: string, authVerifier: string): Promise<string | null> {
    const acc = await this.repo.findByEmail(email);
    if (!acc) {
      // Burn comparable time so timing doesn't reveal whether the account exists.
      await hashVerifier(authVerifier).catch(() => "");
      return null;
    }
    const ok = await argon2Verify({ password: authVerifier, hash: acc.authHash }).catch(() => false);
    return ok ? acc.id : null;
  }
}

/** Slow Argon2id hash (encoded) of the client-derived verifier — what we store. */
async function hashVerifier(verifier: string): Promise<string> {
  return argon2id({
    password: verifier,
    salt: randomBytes(16),
    parallelism: 1,
    iterations: 3,
    memorySize: 19456,
    hashLength: 32,
    outputType: "encoded",
  });
}

function decoySalt(email: string): string {
  // Stable pseudo-salt so repeated probes for the same email look consistent.
  let h = 0;
  for (const c of email) h = (h * 31 + c.charCodeAt(0)) >>> 0;
  return Buffer.from(String(h).padStart(16, "0")).toString("base64");
}

export function safeStrEqual(a: string, b: string): boolean {
  const ba = Buffer.from(a), bb = Buffer.from(b);
  return ba.length === bb.length && timingSafeEqual(ba, bb);
}
