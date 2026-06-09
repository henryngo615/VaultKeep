import { describe, it, expect } from "vitest";
import { VaultApp } from "../src/core/vault-app.js";
import { MemoryStore, FileStore } from "../src/core/local-store.js";
import {
  BiometricUnlock,
  type SecureEnclave,
  type TokenStore,
} from "../src/core/biometric.js";
import type { Transport, RemoteItem, PushOutcome } from "../src/core/sync-client.js";
import { generateSalt } from "@vaultkeep/crypto";
import { VaultService } from "@vaultkeep/server/vault/vault.service.js";
import { InMemoryVaultRepository } from "@vaultkeep/server/vault/vault.repository.js";

const FAST_KDF = { memoryKiB: 8192, iterations: 2, parallelism: 1 };

/**
 * Bridge the real server VaultService to the desktop Transport interface, so
 * the desktop app talks to the ACTUAL sync engine (real conflict resolution),
 * just without an HTTP socket in the way.
 */
function serverTransport(svc: VaultService, userId: string): Transport {
  return {
    async pull(since?: string): Promise<RemoteItem[]> {
      return svc.pull(userId, since);
    },
    async push(id, ciphertext, baseVersion): Promise<PushOutcome> {
      const r = await svc.push(userId, { id, ciphertext, baseVersion });
      if (r.status === "ok") return { status: "ok", version: r.version };
      return { status: "conflict", serverVersion: r.serverVersion, server: r.server };
    },
  };
}

describe("VaultApp end-to-end", () => {
  it("rejects unlock with the wrong master password", async () => {
    const salt = generateSalt();
    // Seed a vault encrypted under the RIGHT password.
    const store = new MemoryStore();
    const right = new VaultApp(salt, store, null, FAST_KDF);
    await right.unlock("correct-password");
    await right.add({ type: "login", title: "Amazon", password: "s3cret" });
    right.lock();

    // A different password must fail (GCM auth tag won't verify).
    const wrong = new VaultApp(salt, store, null, FAST_KDF);
    await expect(wrong.unlock("WRONG-password")).rejects.toThrow();
  });

  it("persists items encrypted at rest and reloads them", async () => {
    const salt = generateSalt();
    const store = new MemoryStore();

    const a = new VaultApp(salt, store, null, FAST_KDF);
    await a.unlock("master");
    await a.add({ type: "login", title: "GitHub", username: "henry", password: "pw1" });
    a.lock();

    // The on-disk blob must contain neither the password NOR the title/username.
    const raw = (await store.readRaw()) ?? "";
    expect(raw).not.toContain("pw1");
    expect(raw).not.toContain("GitHub");
    expect(raw).not.toContain("henry");

    // Reopen and decrypt.
    const b = new VaultApp(salt, store, null, FAST_KDF);
    await b.unlock("master");
    expect(b.list()[0].password).toBe("pw1");
  });

  it("syncs a secret from one device to another, zero-knowledge", async () => {
    const salt = generateSalt();
    const svc = new VaultService(new InMemoryVaultRepository());
    const transport = serverTransport(svc, "user-1");

    // Device A creates an item and pushes it.
    const mac = new VaultApp(salt, new MemoryStore(), transport, FAST_KDF);
    await mac.unlock("master-pw");
    await mac.add({ type: "login", title: "Bank", username: "h@x.com", password: "vault-pw" });
    const up = await mac.sync();
    expect(up.pushed).toBe(1);

    // The SERVER must only hold ciphertext — never the plaintext password.
    const stored = JSON.stringify(await svc.pull("user-1"));
    expect(stored).not.toContain("vault-pw");
    expect(stored).not.toContain("Bank");

    // Device B (same account/password, fresh local store) pulls and decrypts.
    const win = new VaultApp(salt, new MemoryStore(), transport, FAST_KDF);
    await win.unlock("master-pw");
    const down = await win.sync();
    expect(down.pulled).toBe(1);
    const item = win.list()[0];
    expect(item.title).toBe("Bank");
    expect(item.password).toBe("vault-pw");
  });

  it("resolves a cross-device conflict by taking the server's newer copy", async () => {
    const salt = generateSalt();
    const svc = new VaultService(new InMemoryVaultRepository());
    const t = serverTransport(svc, "user-2");

    const mac = new VaultApp(salt, new MemoryStore(), t, FAST_KDF);
    await mac.unlock("pw");
    const item = await mac.add({ type: "login", title: "Site", password: "v1" });
    await mac.sync(); // now at version 1 on server

    const win = new VaultApp(salt, new MemoryStore(), t, FAST_KDF);
    await win.unlock("pw");
    await win.sync(); // win learns version 1

    // Windows edits and pushes -> server v2.
    await win.update(item.id, { password: "v2-from-win" });
    expect((await win.sync()).pushed).toBe(1);

    // Mac edits the SAME item while still at v1 -> conflict, takes server copy.
    await mac.update(item.id, { password: "v2-from-mac-LOSES" });
    const res = await mac.sync();
    expect(res.conflicts).toBe(1);
    expect(mac.get(item.id)!.password).toBe("v2-from-win");
  });
});

describe("FileStore persistence (key-free, single blob)", () => {
  it("round-trips a vault through a fake filesystem", async () => {
    const salt = generateSalt();
    // A tiny in-memory fake of the fs API FileStore expects.
    const files = new Map<string, string>();
    const fs = {
      readFile: async (p: string) => {
        if (!files.has(p)) throw new Error("ENOENT");
        return files.get(p)!;
      },
      writeFile: async (p: string, d: string) => void files.set(p, d),
    };

    const store1 = new FileStore("/tmp/vault.enc", fs);
    const a = new VaultApp(salt, store1, null, FAST_KDF);
    await a.unlock("master");
    await a.add({ type: "login", title: "Proton", password: "fs-secret" });
    a.lock();

    // The bytes written to "disk" leak nothing.
    expect(files.get("/tmp/vault.enc")).not.toContain("fs-secret");
    expect(files.get("/tmp/vault.enc")).not.toContain("Proton");

    // A brand-new FileStore over the same fake fs reloads and decrypts.
    const b = new VaultApp(salt, new FileStore("/tmp/vault.enc", fs), null, FAST_KDF);
    await b.unlock("master");
    expect(b.list()[0].password).toBe("fs-secret");
  });
});

describe("BiometricUnlock (Touch ID / Windows Hello)", () => {
  // A fake enclave: "encryption" is reversible tagging; prompt result is scripted.
  function fakeEnclave(opts: { available: boolean; pass: boolean }): SecureEnclave {
    return {
      isAvailable: () => opts.available,
      promptUser: async () => opts.pass,
      encrypt: (s) => "enc(" + Buffer.from(s).toString("base64") + ")",
      decrypt: (c) => {
        const m = /^enc\((.*)\)$/.exec(c);
        if (!m) throw new Error("bad token");
        return Buffer.from(m[1], "base64").toString();
      },
    };
  }
  function memTokens(): TokenStore {
    let t: string | null = null;
    return {
      read: async () => t,
      write: async (v) => void (t = v),
      clear: async () => void (t = null),
    };
  }

  it("enrolls and recovers the master password after a passing prompt", async () => {
    const bio = new BiometricUnlock(fakeEnclave({ available: true, pass: true }), memTokens());
    expect(await bio.isEnrolled()).toBe(false);
    await bio.enroll("hunter2");
    expect(await bio.isEnrolled()).toBe(true);
    expect(await bio.recoverPassword()).toBe("hunter2");
  });

  it("returns null when the biometric prompt is declined", async () => {
    const bio = new BiometricUnlock(fakeEnclave({ available: true, pass: false }), memTokens());
    await bio.enroll("hunter2");
    expect(await bio.recoverPassword()).toBeNull();
  });

  it("never stores the plaintext password in the token", async () => {
    const tokens = memTokens();
    const bio = new BiometricUnlock(fakeEnclave({ available: true, pass: true }), tokens);
    await bio.enroll("super-secret-pw");
    expect(await tokens.read()).not.toContain("super-secret-pw");
  });

  it("refuses to enroll when no secure enclave is present", async () => {
    const bio = new BiometricUnlock(fakeEnclave({ available: false, pass: true }), memTokens());
    await expect(bio.enroll("pw")).rejects.toThrow();
  });

  it("forgets the credential on unenroll", async () => {
    const bio = new BiometricUnlock(fakeEnclave({ available: true, pass: true }), memTokens());
    await bio.enroll("pw");
    await bio.unenroll();
    expect(await bio.isEnrolled()).toBe(false);
    expect(await bio.recoverPassword()).toBeNull();
  });
});
