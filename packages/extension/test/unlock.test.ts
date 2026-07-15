import { describe, it, expect } from "vitest";
import { createCipheriv, createHmac, randomBytes } from "node:crypto";
import { argon2id } from "hash-wasm";
import {
  deriveMasterKey,
  deriveAuthVerifier,
  decryptBlob,
  zeroKey,
  toB64,
} from "../src/vaultcrypto.js";
import { SyncClient, type FetchLike } from "../src/sync.js";
import { unlockVault } from "../src/unlock.js";
import { SessionStore, InMemorySessionBackend } from "../src/session.js";

/**
 * The reference implementations here (node:crypto AES-GCM + HMAC, hash-wasm
 * Argon2id) are exactly what @vaultkeep/crypto does — proving the extension's
 * WebCrypto port is byte-compatible with vaults written by the desktop/web
 * clients.
 */

const KDF = { memoryKiB: 1024, iterations: 1, parallelism: 1 }; // fast test params
const SALT = randomBytes(16).toString("base64");

/** @vaultkeep/crypto's wire format: base64(nonce ‖ ct ‖ tag), AES-256-GCM. */
function referenceEncrypt(key: Uint8Array, plaintext: string): string {
  const nonce = randomBytes(12);
  const cipher = createCipheriv("aes-256-gcm", Buffer.from(key), nonce);
  const ct = Buffer.concat([cipher.update(plaintext, "utf8"), cipher.final()]);
  return Buffer.concat([nonce, ct, cipher.getAuthTag()]).toString("base64");
}

async function referenceKey(password: string): Promise<Uint8Array> {
  return new Uint8Array(
    await argon2id({
      password,
      salt: Buffer.from(SALT, "base64"),
      parallelism: KDF.parallelism,
      iterations: KDF.iterations,
      memorySize: KDF.memoryKiB,
      hashLength: 32,
      outputType: "binary",
    })
  );
}

describe("vaultcrypto (browser port of @vaultkeep/crypto)", () => {
  it("derives the same Argon2id key as the shared crypto core", async () => {
    const ours = await deriveMasterKey("hunter2 but longer", SALT, KDF);
    const reference = await referenceKey("hunter2 but longer");
    expect(toB64(ours)).toBe(toB64(reference));
    expect(ours.length).toBe(32);
  });

  it("derives the same auth verifier as node's HMAC-SHA256", async () => {
    const key = await referenceKey("pw");
    const expected = createHmac("sha256", Buffer.from(key))
      .update("vaultkeep-auth-verifier:pw")
      .digest("base64");
    expect(await deriveAuthVerifier(key, "pw")).toBe(expected);
  });

  it("decrypts blobs written by the node implementation", async () => {
    const key = await referenceKey("pw");
    const blob = referenceEncrypt(key, JSON.stringify({ title: "GitHub", password: "s3cret" }));
    expect(JSON.parse(await decryptBlob(key, blob)).title).toBe("GitHub");
  });

  it("rejects a wrong key via GCM auth-tag verification", async () => {
    const key = await referenceKey("right password");
    const wrong = await referenceKey("wrong password");
    const blob = referenceEncrypt(key, "secret");
    await expect(decryptBlob(wrong, blob)).rejects.toThrow();
  });

  it("rejects tampered ciphertext", async () => {
    const key = await referenceKey("pw");
    const blob = Buffer.from(referenceEncrypt(key, "secret"), "base64");
    blob[14] ^= 0xff; // flip one ciphertext byte
    await expect(decryptBlob(key, blob.toString("base64"))).rejects.toThrow();
  });

  it("zeroKey wipes the key in place", async () => {
    const key = await referenceKey("pw");
    zeroKey(key);
    expect(key.every((b) => b === 0)).toBe(true);
  });
});

// ---------------------------------------------------------------------------

/** A fake sync server implementing the real API contract over stubbed fetch. */
function fakeServer(vaultKey: Uint8Array, expectedVerifier: string) {
  const items = [
    { id: "i1", ciphertext: referenceEncrypt(vaultKey, JSON.stringify({ title: "GitHub", username: "henry", password: "gh-pass", url: "https://github.com" })), version: 1 },
    { id: "i2", ciphertext: referenceEncrypt(vaultKey, JSON.stringify({ title: "Mail", username: "h@x.com", password: "mail-pass", url: "https://mail.example.com" })), version: 3 },
    { id: "bad", ciphertext: "AAAA" + referenceEncrypt(vaultKey, "x").slice(4), version: 1 }, // tampered row
  ];
  const state = { deviceEnrolled: false, approved: true, log: [] as string[] };

  const fetchImpl: FetchLike = async (url, init) => {
    const path = new URL(url).pathname;
    const body = init?.body ? JSON.parse(init.body as string) : {};
    state.log.push(path);
    const reply = (status: number, data: unknown) =>
      new Response(JSON.stringify(data), { status });

    if (path === "/auth/kdf") return reply(200, { kdfSalt: SALT, kdfMemoryKiB: KDF.memoryKiB, kdfIterations: KDF.iterations, kdfParallel: KDF.parallelism });
    if (path === "/auth/login") {
      if (body.authVerifier !== expectedVerifier) return reply(401, { error: "invalid credentials" });
      if (!body.deviceId) return reply(200, { userId: "u1", needsDevice: true });
      return reply(200, { token: "pre-mfa", userId: "u1", mfaRequired: true });
    }
    if (path === "/devices/enroll") {
      state.deviceEnrolled = true;
      return reply(201, { device: { id: "dev-ext", approved: true } });
    }
    if (path === "/auth/mfa") {
      return body.code === "123456" ? reply(200, { token: "full" }) : reply(401, { error: "invalid MFA code" });
    }
    if (path === "/vault/items") {
      if (init?.headers && (init.headers as any).authorization !== "Bearer full") return reply(403, { error: "MFA required" });
      if (!state.approved) return reply(403, { error: "device not approved" });
      return reply(200, { items });
    }
    return reply(404, { error: "not found" });
  };

  return { fetchImpl, state };
}

describe("unlockVault (popup unlock orchestration)", () => {
  async function setup(password = "correct horse") {
    const vaultKey = await referenceKey(password);
    const verifier = createHmac("sha256", Buffer.from(vaultKey))
      .update("vaultkeep-auth-verifier:" + password)
      .digest("base64");
    return { vaultKey, server: fakeServer(vaultKey, verifier) };
  }

  it("enrolls on first use, satisfies MFA, and decrypts the vault", async () => {
    const { server } = await setup();
    const result = await unlockVault(new SyncClient("http://x", server.fetchImpl), {
      email: "me@x.com", password: "correct horse", code: "123456",
    });
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(server.state.deviceEnrolled).toBe(true);
    expect(result.deviceId).toBe("dev-ext");
    expect(result.credentials.map((c) => c.title)).toEqual(["GitHub", "Mail"]);
    expect(result.credentials[0].password).toBe("gh-pass");
    expect(result.skipped).toBe(1); // the tampered row is skipped, not shown
  });

  it("skips enrollment when a deviceId is already known", async () => {
    const { server } = await setup();
    const result = await unlockVault(new SyncClient("http://x", server.fetchImpl), {
      email: "me@x.com", password: "correct horse", code: "123456", deviceId: "dev-ext",
    });
    expect(result.ok).toBe(true);
    expect(server.state.log).not.toContain("/devices/enroll");
  });

  it("fails cleanly on a wrong master password (verifier mismatch)", async () => {
    const { server } = await setup("the real password");
    const result = await unlockVault(new SyncClient("http://x", server.fetchImpl), {
      email: "me@x.com", password: "not the password", code: "123456",
    });
    expect(result).toEqual({ ok: false, stage: "login", reason: "invalid credentials" });
  });

  it("fails cleanly on a wrong TOTP code", async () => {
    const { server } = await setup();
    const result = await unlockVault(new SyncClient("http://x", server.fetchImpl), {
      email: "me@x.com", password: "correct horse", code: "000000",
    });
    expect(result).toEqual({ ok: false, stage: "mfa", reason: "invalid MFA code" });
  });

  it("explains an unapproved device instead of failing opaquely", async () => {
    const { server } = await setup();
    server.state.approved = false;
    const result = await unlockVault(new SyncClient("http://x", server.fetchImpl), {
      email: "me@x.com", password: "correct horse", code: "123456", deviceId: "dev-ext",
    });
    expect(result.ok).toBe(false);
    expect(!result.ok && result.reason).toMatch(/awaiting approval/);
  });
});

// ---------------------------------------------------------------------------

describe("SessionStore (auto-lock session cache)", () => {
  const creds = [{ id: "1", title: "GitHub", username: "h", password: "p", url: "https://github.com" }];

  function store(autoLockMs: number, clock: { t: number }) {
    return new SessionStore(new InMemorySessionBackend(), autoLockMs, () => clock.t);
  }

  it("serves credentials while unlocked and none after lock()", async () => {
    const clock = { t: 0 };
    const s = store(1000, clock);
    await s.activate(creds);
    expect(await s.credentials()).toHaveLength(1);
    await s.lock();
    expect(await s.credentials()).toBeNull();
    expect((await s.status()).unlocked).toBe(false);
  });

  it("auto-locks when the expiry passes, even with no timer", async () => {
    const clock = { t: 0 };
    const s = store(1000, clock);
    await s.activate(creds);
    clock.t = 1001;
    expect(await s.credentials()).toBeNull(); // expired -> cleared on read
    clock.t = 0;
    expect(await s.credentials()).toBeNull(); // and it stays cleared
  });

  it("touch() slides the expiry on activity", async () => {
    const clock = { t: 0 };
    const s = store(1000, clock);
    await s.activate(creds);
    clock.t = 900;
    await s.touch();
    clock.t = 1800; // past the original expiry, within the refreshed one
    expect(await s.credentials()).toHaveLength(1);
  });

  it("never contains key material — only credentials and an expiry", async () => {
    const backend = new InMemorySessionBackend();
    const s = new SessionStore(backend, 1000, () => 0);
    await s.activate(creds);
    const raw = JSON.stringify(await backend.get());
    expect(Object.keys((await backend.get())!).sort()).toEqual(["credentials", "expiresAt"]);
    expect(raw).not.toMatch(/key|master|argon/i);
  });
});
