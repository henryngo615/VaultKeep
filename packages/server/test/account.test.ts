import { describe, it, expect } from "vitest";
import { AccountService } from "../src/auth/account.service.js";
import { InMemoryAccountRepository } from "../src/auth/account.repository.js";
import {
  DeviceService,
  InMemoryDeviceRepository,
} from "../src/devices/device.service.js";
import { generateSigningKeys, generateExchangeKeys, signMessage } from "@vaultkeep/crypto";

function newAccounts() {
  return new AccountService(new InMemoryAccountRepository());
}

const SALT = Buffer.from("0123456789abcdef").toString("base64");
const VERIFIER = "client-derived-auth-verifier-abc123";

describe("AccountService (zero-knowledge auth)", () => {
  it("registers a user and verifies a correct login", async () => {
    const svc = newAccounts();
    const { userId } = await svc.register({ email: "a@b.com", authVerifier: VERIFIER, kdfSalt: SALT });
    expect(userId).toBeTruthy();
    expect(await svc.verifyLogin("a@b.com", VERIFIER)).toBe(userId);
  });

  it("rejects a wrong verifier", async () => {
    const svc = newAccounts();
    await svc.register({ email: "a@b.com", authVerifier: VERIFIER, kdfSalt: SALT });
    expect(await svc.verifyLogin("a@b.com", "wrong-verifier-000000")).toBeNull();
  });

  it("returns null (not an error) for an unknown email", async () => {
    const svc = newAccounts();
    expect(await svc.verifyLogin("nobody@x.com", VERIFIER)).toBeNull();
  });

  it("never stores the verifier in plaintext (only an argon2 hash)", async () => {
    const repo = new InMemoryAccountRepository();
    const svc = new AccountService(repo);
    await svc.register({ email: "a@b.com", authVerifier: VERIFIER, kdfSalt: SALT });
    const rec = await repo.findByEmail("a@b.com");
    expect(rec!.authHash).not.toContain(VERIFIER);
    expect(rec!.authHash.startsWith("$argon2id$")).toBe(true);
  });

  it("rejects duplicate email registration", async () => {
    const svc = newAccounts();
    await svc.register({ email: "a@b.com", authVerifier: VERIFIER, kdfSalt: SALT });
    await expect(
      svc.register({ email: "a@b.com", authVerifier: VERIFIER, kdfSalt: SALT })
    ).rejects.toThrow();
  });

  it("returns stable decoy KDF params for unknown emails (no enumeration)", async () => {
    const svc = newAccounts();
    const p1 = await svc.kdfParamsFor("ghost@x.com");
    const p2 = await svc.kdfParamsFor("ghost@x.com");
    expect(p1.kdfSalt).toBe(p2.kdfSalt); // stable per-address
  });

  it("rejects invalid email and weak verifier", async () => {
    const svc = newAccounts();
    await expect(svc.register({ email: "nope", authVerifier: VERIFIER, kdfSalt: SALT })).rejects.toThrow();
    await expect(svc.register({ email: "a@b.com", authVerifier: "short", kdfSalt: SALT })).rejects.toThrow();
  });
});

describe("DeviceService (trust + approval)", () => {
  function dev() {
    return new DeviceService(new InMemoryDeviceRepository());
  }
  function keys() {
    return { sign: generateSigningKeys(), exch: generateExchangeKeys() };
  }

  it("auto-approves the first device, leaves later ones pending", async () => {
    const svc = dev();
    const k1 = keys(), k2 = keys();
    const d1 = await svc.enroll({ userId: "u", name: "Mac", platform: "macos", publicKey: k1.exch.publicKey, signingPublicKey: k1.sign.publicKey });
    const d2 = await svc.enroll({ userId: "u", name: "iPhone", platform: "ios", publicKey: k2.exch.publicKey, signingPublicKey: k2.sign.publicKey });
    expect(d1.approved).toBe(true);
    expect(d2.approved).toBe(false);
  });

  it("approves a pending device with a valid signature from a trusted device", async () => {
    const svc = dev();
    const k1 = keys(), k2 = keys();
    const d1 = await svc.enroll({ userId: "u", name: "Mac", platform: "macos", publicKey: k1.exch.publicKey, signingPublicKey: k1.sign.publicKey });
    const d2 = await svc.enroll({ userId: "u", name: "iPhone", platform: "ios", publicKey: k2.exch.publicKey, signingPublicKey: k2.sign.publicKey });

    const sig = signMessage(k1.sign.privateKey, `approve-device:${d2.id}`);
    const res = await svc.approve("u", d1.id, d2.id, sig);
    expect(res.ok).toBe(true);
    expect(await svc.isApproved("u", d2.id)).toBe(true);
  });

  it("rejects approval signed by an UNTRUSTED device", async () => {
    const svc = dev();
    const k1 = keys(), k2 = keys(), k3 = keys();
    await svc.enroll({ userId: "u", name: "Mac", platform: "macos", publicKey: k1.exch.publicKey, signingPublicKey: k1.sign.publicKey });
    const d2 = await svc.enroll({ userId: "u", name: "iPhone", platform: "ios", publicKey: k2.exch.publicKey, signingPublicKey: k2.sign.publicKey });
    const d3 = await svc.enroll({ userId: "u", name: "PC", platform: "windows", publicKey: k3.exch.publicKey, signingPublicKey: k3.sign.publicKey });

    // d3 (unapproved) tries to approve d2 — must fail even with a valid signature.
    const sig = signMessage(k3.sign.privateKey, `approve-device:${d2.id}`);
    const res = await svc.approve("u", d3.id, d2.id, sig);
    expect(res.ok).toBe(false);
  });

  it("rejects a forged signature", async () => {
    const svc = dev();
    const k1 = keys(), k2 = keys(), kEvil = keys();
    const d1 = await svc.enroll({ userId: "u", name: "Mac", platform: "macos", publicKey: k1.exch.publicKey, signingPublicKey: k1.sign.publicKey });
    const d2 = await svc.enroll({ userId: "u", name: "iPhone", platform: "ios", publicKey: k2.exch.publicKey, signingPublicKey: k2.sign.publicKey });

    // Signature made with the WRONG key, presented as if from d1.
    const forged = signMessage(kEvil.sign.privateKey, `approve-device:${d2.id}`);
    const res = await svc.approve("u", d1.id, d2.id, forged);
    expect(res.ok).toBe(false);
    expect(await svc.isApproved("u", d2.id)).toBe(false);
  });
});
