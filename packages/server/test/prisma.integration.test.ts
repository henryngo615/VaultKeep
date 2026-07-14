import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { generateExchangeKeys, generateSigningKeys, signMessage } from "@vaultkeep/crypto";
import { PrismaClient } from "../src/generated/prisma/client.js";
import { PrismaPg } from "@prisma/adapter-pg";
import {
  PrismaVaultRepository,
  PrismaAccountRepository,
  PrismaDeviceRepository,
  PrismaMfaRepository,
  PrismaPasskeyRepository,
} from "../src/prisma/adapters.js";
import { VaultService } from "../src/vault/vault.service.js";
import { AccountService } from "../src/auth/account.service.js";
import { DeviceService } from "../src/devices/device.service.js";
import { MfaService } from "../src/mfa/mfa.service.js";
import { currentCode } from "../src/mfa/totp.service.js";
import { startLivePostgres, migrateDeploy, type LiveDb } from "./helpers/live-postgres.js";

/**
 * The same service flows the in-memory suites prove, run against a REAL
 * Postgres through the Prisma adapters. Uses DATABASE_URL when set (e.g.
 * docker-compose), otherwise boots a throwaway embedded Postgres.
 */

let db: LiveDb;
let prisma: PrismaClient;
let vault: VaultService;
let accounts: AccountService;
let devices: DeviceService;
let mfa: MfaService;

beforeAll(async () => {
  db = await startLivePostgres();
  migrateDeploy(db.url);
  prisma = new PrismaClient({ adapter: new PrismaPg({ connectionString: db.url }) });
  vault = new VaultService(new PrismaVaultRepository(prisma));
  accounts = new AccountService(new PrismaAccountRepository(prisma));
  devices = new DeviceService(new PrismaDeviceRepository(prisma));
  mfa = new MfaService(new PrismaMfaRepository(prisma));
}, 180_000);

afterAll(async () => {
  await prisma?.$disconnect();
  await db?.stop();
}, 60_000);

describe("Prisma adapters against live Postgres", () => {
  it("registers an account and verifies login (zero-knowledge verifier)", async () => {
    const verifier = "client-derived-verifier-abc123";
    const { userId } = await accounts.register({
      email: "pg@example.com",
      authVerifier: verifier,
      kdfSalt: "c2FsdA==",
    });
    expect(userId).toBeTruthy();

    expect(await accounts.verifyLogin("pg@example.com", verifier)).toBe(userId);
    expect(await accounts.verifyLogin("pg@example.com", "wrong-verifier-000000")).toBeNull();

    // KDF params round-trip so any device can re-derive the encryption key.
    const kdf = await accounts.kdfParamsFor("pg@example.com");
    expect(kdf.kdfSalt).toBe("c2FsdA==");
  });

  it("rejects duplicate email registration with the repo contract error", async () => {
    await accounts.register({
      email: "dupe@example.com",
      authVerifier: "verifier-strong-enough-1",
      kdfSalt: "c2FsdA==",
    });
    await expect(
      accounts.register({
        email: "dupe@example.com",
        authVerifier: "verifier-strong-enough-2",
        kdfSalt: "c2FsdA==",
      })
    ).rejects.toThrow("email already registered");
  });

  it("stores only an Argon2 hash of the verifier — never the verifier itself", async () => {
    const verifier = "super-secret-verifier-material";
    const { userId } = await accounts.register({
      email: "zk@example.com",
      authVerifier: verifier,
      kdfSalt: "c2FsdA==",
    });
    const row = await prisma.user.findUnique({ where: { id: userId } });
    expect(row!.authHash.startsWith("$argon2")).toBe(true);
    expect(row!.authHash).not.toContain(verifier);
    expect(JSON.stringify(row)).not.toContain(verifier);
  });

  it("auto-approves the first device, gates the second on an Ed25519 approval", async () => {
    const { userId } = await accounts.register({
      email: "devices@example.com",
      authVerifier: "verifier-strong-enough-3",
      kdfSalt: "c2FsdA==",
    });
    const firstSigning = generateSigningKeys();
    const first = await devices.enroll({
      userId,
      name: "Mac",
      platform: "macos",
      publicKey: generateExchangeKeys().publicKey,
      signingPublicKey: firstSigning.publicKey,
    });
    expect(first.approved).toBe(true);

    const second = await devices.enroll({
      userId,
      name: "Windows",
      platform: "windows",
      publicKey: generateExchangeKeys().publicKey,
      signingPublicKey: generateSigningKeys().publicKey,
    });
    expect(second.approved).toBe(false);

    // A forged signature must be rejected...
    const forged = await devices.approve(userId, first.id, second.id, "Zm9yZ2Vk");
    expect(forged.ok).toBe(false);
    expect(await devices.isApproved(userId, second.id)).toBe(false);

    // ...and only the trusted device's real signature approves.
    const sig = signMessage(firstSigning.privateKey, `approve-device:${second.id}`);
    const result = await devices.approve(userId, first.id, second.id, sig);
    expect(result.ok).toBe(true);
    expect(await devices.isApproved(userId, second.id)).toBe(true);
  });

  it("runs two-phase TOTP enrollment and login verification", async () => {
    const { userId } = await accounts.register({
      email: "mfa@example.com",
      authVerifier: "verifier-strong-enough-4",
      kdfSalt: "c2FsdA==",
    });
    const { secret } = await mfa.start(userId, "mfa@example.com");
    expect(await mfa.isEnrolled(userId)).toBe(false);
    // A valid code must not pass login verification before confirmation.
    expect(await mfa.verify(userId, currentCode(secret))).toBe(false);

    expect(await mfa.confirm(userId, currentCode(secret))).toBe(true);
    expect(await mfa.isEnrolled(userId)).toBe(true);
    expect(await mfa.verify(userId, currentCode(secret))).toBe(true);
    const wrong = currentCode(secret) === "000000" ? "111111" : "000000";
    expect(await mfa.verify(userId, wrong)).toBe(false);
  });

  it("syncs encrypted blobs with optimistic concurrency", async () => {
    const { userId } = await accounts.register({
      email: "vault@example.com",
      authVerifier: "verifier-strong-enough-5",
      kdfSalt: "c2FsdA==",
    });

    const push1 = await vault.push(userId, {
      id: "item-1",
      ciphertext: "b3BhcXVlLWJsb2ItMQ==",
      baseVersion: null,
    });
    expect(push1).toEqual({ status: "ok", version: 1 });

    const push2 = await vault.push(userId, {
      id: "item-1",
      ciphertext: "b3BhcXVlLWJsb2ItMg==",
      baseVersion: 1,
    });
    expect(push2).toEqual({ status: "ok", version: 2 });

    // A stale edit (based on v1 after v2 landed) must conflict, not overwrite.
    const stale = await vault.push(userId, {
      id: "item-1",
      ciphertext: "b3BhcXVlLWJsb2ItMw==",
      baseVersion: 1,
    });
    expect(stale.status).toBe("conflict");

    const items = await vault.pull(userId);
    expect(items).toHaveLength(1);
    expect(items[0].ciphertext).toBe("b3BhcXVlLWJsb2ItMg=="); // stale write rejected

    await vault.delete(userId, "item-1");
    expect(await vault.pull(userId)).toHaveLength(0);
  });

  it("pull(since) returns only items changed after the cutoff", async () => {
    const { userId } = await accounts.register({
      email: "since@example.com",
      authVerifier: "verifier-strong-enough-6",
      kdfSalt: "c2FsdA==",
    });
    await vault.push(userId, { id: "old", ciphertext: "b2xk", baseVersion: null });
    const cutoff = new Date().toISOString();
    await new Promise((r) => setTimeout(r, 20));
    await vault.push(userId, { id: "new", ciphertext: "bmV3", baseVersion: null });

    const changed = await vault.pull(userId, cutoff);
    expect(changed.map((i) => i.id)).toEqual(["new"]);
  });

  it("persists passkey credentials and sign counters", async () => {
    const { userId } = await accounts.register({
      email: "passkey@example.com",
      authVerifier: "verifier-strong-enough-9",
      kdfSalt: "c2FsdA==",
    });
    const repo = new PrismaPasskeyRepository(prisma);
    await repo.create({
      credentialId: "Y3JlZC1wZw",
      userId,
      publicKeyJwk: JSON.stringify({ kty: "EC", crv: "P-256", x: "eA", y: "eQ" }),
      alg: -7,
      signCount: 0,
      name: "YubiKey",
      createdAt: new Date().toISOString(),
    });
    const stored = await repo.get("Y3JlZC1wZw");
    expect(stored?.userId).toBe(userId);
    expect(stored?.alg).toBe(-7);

    await repo.updateSignCount("Y3JlZC1wZw", 7);
    expect((await repo.get("Y3JlZC1wZw"))?.signCount).toBe(7);
    expect(await repo.listForUser(userId)).toHaveLength(1);
  });

  it("isolates tenants: the same item id for two users never collides", async () => {
    const a = await accounts.register({
      email: "tenant-a@example.com",
      authVerifier: "verifier-strong-enough-7",
      kdfSalt: "c2FsdA==",
    });
    const b = await accounts.register({
      email: "tenant-b@example.com",
      authVerifier: "verifier-strong-enough-8",
      kdfSalt: "c2FsdA==",
    });

    await vault.push(a.userId, { id: "shared-id", ciphertext: "dXNlci1B", baseVersion: null });
    // Same client-chosen id, different user — must create, not overwrite.
    const pushB = await vault.push(b.userId, { id: "shared-id", ciphertext: "dXNlci1C", baseVersion: null });
    expect(pushB).toEqual({ status: "ok", version: 1 });

    const itemA = await vault.pull(a.userId);
    expect(itemA).toHaveLength(1);
    expect(itemA[0].ciphertext).toBe("dXNlci1B"); // untouched by B's push

    // And neither user can see (or delete) the other's row.
    await vault.delete(b.userId, "shared-id");
    expect((await vault.pull(a.userId))[0].ciphertext).toBe("dXNlci1B");
  });
});
