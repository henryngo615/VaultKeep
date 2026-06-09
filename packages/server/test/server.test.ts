import { describe, it, expect } from "vitest";
import { resolvePush } from "../src/sync/conflict.js";
import { VaultService } from "../src/vault/vault.service.js";
import { InMemoryVaultRepository } from "../src/vault/vault.repository.js";
import { TokenService } from "../src/auth/token.service.js";
import {
  generateSecret,
  verifyTOTP,
  currentCode,
  otpauthURI,
} from "../src/mfa/totp.service.js";

describe("conflict resolution", () => {
  it("creates a new item when neither side has a version", () => {
    expect(resolvePush({ current: null }, { baseVersion: null })).toEqual({
      kind: "create",
      newVersion: 1,
    });
  });

  it("accepts a clean update based on the current version", () => {
    expect(resolvePush({ current: 5 }, { baseVersion: 5 })).toEqual({
      kind: "update",
      newVersion: 6,
    });
  });

  it("rejects a stale update as a conflict", () => {
    expect(resolvePush({ current: 7 }, { baseVersion: 3 })).toEqual({
      kind: "conflict",
      serverVersion: 7,
    });
  });

  it("treats editing a server-unknown item as a conflict", () => {
    expect(resolvePush({ current: null }, { baseVersion: 2 })).toEqual({
      kind: "conflict",
      serverVersion: 0,
    });
  });
});

describe("VaultService sync engine", () => {
  it("stores and pulls back ciphertext only", async () => {
    const svc = new VaultService(new InMemoryVaultRepository());
    const r = await svc.push("user1", {
      id: "item1",
      ciphertext: "BLOB==",
      baseVersion: null,
    });
    expect(r).toEqual({ status: "ok", version: 1 });

    const items = await svc.pull("user1");
    expect(items).toHaveLength(1);
    expect(items[0].ciphertext).toBe("BLOB==");
  });

  it("isolates users from each other", async () => {
    const svc = new VaultService(new InMemoryVaultRepository());
    await svc.push("alice", { id: "x", ciphertext: "A", baseVersion: null });
    expect(await svc.pull("bob")).toHaveLength(0);
  });

  it("bumps version on successive clean updates", async () => {
    const svc = new VaultService(new InMemoryVaultRepository());
    await svc.push("u", { id: "i", ciphertext: "v1", baseVersion: null });
    const r2 = await svc.push("u", { id: "i", ciphertext: "v2", baseVersion: 1 });
    expect(r2).toEqual({ status: "ok", version: 2 });
  });

  it("rejects a stale push and returns the server's copy", async () => {
    const svc = new VaultService(new InMemoryVaultRepository());
    await svc.push("u", { id: "i", ciphertext: "v1", baseVersion: null });
    await svc.push("u", { id: "i", ciphertext: "v2", baseVersion: 1 });
    // A second device still thinks it's at v1:
    const stale = await svc.push("u", {
      id: "i",
      ciphertext: "oops",
      baseVersion: 1,
    });
    expect(stale.status).toBe("conflict");
    if (stale.status === "conflict") {
      expect(stale.serverVersion).toBe(2);
      expect(stale.server?.ciphertext).toBe("v2"); // newer data preserved
    }
  });

  it("supports incremental pull via `since`", async () => {
    const svc = new VaultService(new InMemoryVaultRepository());
    await svc.push("u", { id: "old", ciphertext: "o", baseVersion: null });
    const cutoff = new Date(Date.now() + 5).toISOString();
    await new Promise((r) => setTimeout(r, 10));
    await svc.push("u", { id: "new", ciphertext: "n", baseVersion: null });
    const recent = await svc.pull("u", cutoff);
    expect(recent.map((i) => i.id)).toEqual(["new"]);
  });
});

describe("TokenService (HS256 JWT)", () => {
  const svc = new TokenService("super-secret-test-key-1234");

  it("round-trips claims", () => {
    const t = svc.issue({ sub: "u1", did: "d1", mfa: true });
    const claims = svc.verify(t);
    expect(claims?.sub).toBe("u1");
    expect(claims?.mfa).toBe(true);
  });

  it("rejects a tampered token", () => {
    const t = svc.issue({ sub: "u1", did: "d1", mfa: true });
    const forged = t.slice(0, -2) + (t.endsWith("A") ? "BB" : "AA");
    expect(svc.verify(forged)).toBeNull();
  });

  it("rejects a token signed with a different secret", () => {
    const other = new TokenService("a-totally-different-key-xyz");
    expect(svc.verify(other.issue({ sub: "u", did: "d", mfa: false }))).toBeNull();
  });

  it("rejects an expired token", () => {
    const t = svc.issue({ sub: "u", did: "d", mfa: true }, -1);
    expect(svc.verify(t)).toBeNull();
  });
});

describe("TOTP MFA", () => {
  it("verifies the code valid for the current step", () => {
    const secret = generateSecret();
    expect(verifyTOTP(secret, currentCode(secret))).toBe(true);
  });

  it("rejects an obviously wrong code", () => {
    const secret = generateSecret();
    const wrong = currentCode(secret) === "000000" ? "111111" : "000000";
    expect(verifyTOTP(secret, wrong)).toBe(false);
  });

  it("emits a scannable otpauth URI", () => {
    expect(otpauthURI(generateSecret(), "user@example.com")).toContain(
      "otpauth://totp/"
    );
  });
});
