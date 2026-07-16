import { describe, it, expect } from "vitest";
import { randomBytes, createCipheriv, createDecipheriv } from "node:crypto";
import { BiometricUnlock, type SecureEnclave, type TokenStore } from "../src/core/biometric.js";
import { VaultApp } from "../src/core/vault-app.js";
import { MemoryStore } from "../src/core/local-store.js";

/**
 * Fully mockable biometric layer — no Electron anywhere. The mock enclave is a
 * real AES-GCM keystore with a device-local key, plus scriptable availability
 * and prompt outcomes, so every acceptance path is exercised:
 * enroll → biometric unlock, declined prompt, unavailable hardware,
 * disable-wipes-key, stale/tampered wrapped blobs.
 */

class MockEnclave implements SecureEnclave {
  available = true;
  promptResult = true;
  promptCount = 0;
  private readonly deviceKey = randomBytes(32);

  async isAvailable() {
    return this.available;
  }
  async promptUser() {
    this.promptCount++;
    return this.promptResult;
  }
  encrypt(plaintext: string): string {
    const nonce = randomBytes(12);
    const c = createCipheriv("aes-256-gcm", this.deviceKey, nonce);
    const ct = Buffer.concat([c.update(plaintext, "utf8"), c.final()]);
    return Buffer.concat([nonce, ct, c.getAuthTag()]).toString("base64");
  }
  decrypt(b64: string): string {
    const blob = Buffer.from(b64, "base64");
    const d = createDecipheriv("aes-256-gcm", this.deviceKey, blob.subarray(0, 12));
    d.setAuthTag(blob.subarray(blob.length - 16));
    return Buffer.concat([d.update(blob.subarray(12, blob.length - 16)), d.final()]).toString("utf8");
  }
}

class MemoryTokenStore implements TokenStore {
  token: string | null = null;
  async read() {
    return this.token;
  }
  async write(t: string) {
    this.token = t;
  }
  async clear() {
    this.token = null;
  }
}

const SALT = randomBytes(16).toString("base64");
const KDF = { memoryKiB: 1024, iterations: 1, parallelism: 1 };

function setup() {
  const enclave = new MockEnclave();
  const tokens = new MemoryTokenStore();
  return { enclave, tokens, bio: new BiometricUnlock(enclave, tokens) };
}

/** Password-unlock a vault with one item, then enroll its key. */
async function enrolledVault(bio: BiometricUnlock) {
  const store = new MemoryStore();
  const app = new VaultApp(SALT, store, null, KDF);
  await app.unlock("master password 1");
  await app.add({ type: "login", title: "GitHub", username: "h", password: "p", url: "" });
  const key = app.snapshotKey();
  await bio.enroll(key, SALT, null);
  key.fill(0); // caller wipes its copy after wrapping
  app.lock();
  return store;
}

describe("BiometricUnlock (wrapped master key behind the OS keystore)", () => {
  it("after one password unlock + enroll, a biometric prompt unlocks the vault", async () => {
    const { enclave, bio } = setup();
    const store = await enrolledVault(bio);

    const recovered = await bio.recoverKey();
    expect(enclave.promptCount).toBe(1);
    expect(recovered).not.toBeNull();
    expect(recovered!.saltB64).toBe(SALT);
    expect(recovered!.userId).toBeNull();

    // No password, no KDF — the unwrapped key opens the same vault.
    const app = new VaultApp(recovered!.saltB64, store, null, KDF);
    await app.unlockWithKey(recovered!.key);
    expect(app.list().map((i) => i.title)).toEqual(["GitHub"]);
  });

  it("a declined biometric prompt yields no key", async () => {
    const { enclave, bio } = setup();
    await enrolledVault(bio);
    enclave.promptResult = false;
    expect(await bio.recoverKey()).toBeNull();
  });

  it("enroll is refused when no biometric keystore is available", async () => {
    const { enclave, bio } = setup();
    enclave.available = false;
    await expect(bio.enroll(randomBytes(32), SALT, null)).rejects.toThrow(/unavailable/);
    expect(await bio.isEnrolled()).toBe(false);
  });

  it("hardware disappearing after enrollment falls back to the password", async () => {
    const { enclave, tokens, bio } = setup();
    await enrolledVault(bio);
    enclave.available = false;
    expect(await bio.isEnrolled()).toBe(false);
    expect(await bio.recoverKey()).toBeNull();
    expect(tokens.token).not.toBeNull(); // untouched — comes back with the hardware
  });

  it("disabling biometrics wipes the wrapped key from the keystore", async () => {
    const { tokens, bio } = setup();
    await enrolledVault(bio);
    expect(tokens.token).not.toBeNull();
    await bio.unenroll();
    expect(tokens.token).toBeNull();
    expect(await bio.isEnrolled()).toBe(false);
    expect(await bio.recoverKey()).toBeNull();
  });

  it("a tampered wrapped blob is rejected AND wiped (password fallback)", async () => {
    const { tokens, bio } = setup();
    await enrolledVault(bio);
    const blob = Buffer.from(tokens.token!, "base64");
    blob[15] ^= 0xff;
    tokens.token = blob.toString("base64");

    expect(await bio.recoverKey()).toBeNull();
    expect(tokens.token).toBeNull(); // stale enrollment cleaned up
  });

  it("a stale wrapped key cannot open a re-keyed vault (GCM gate)", async () => {
    const { bio } = setup();
    const store = await enrolledVault(bio);

    // The user changes their master password -> vault re-encrypted.
    const app = new VaultApp(SALT, store, null, KDF);
    await app.unlock("master password 1");
    const items = app.list();
    const rekeyed = new VaultApp(SALT, new MemoryStore(), null, KDF);
    await rekeyed.unlock("NEW master password");
    for (const it of items) await rekeyed.add({ ...it });
    await store.writeRaw((await (rekeyed as any).store.readRaw())!);

    const recovered = await bio.recoverKey();
    const reopened = new VaultApp(SALT, store, null, KDF);
    await expect(reopened.unlockWithKey(recovered!.key)).rejects.toThrow();
  });

  it("enrollment stores the account context for per-account vaults", async () => {
    const { bio } = setup();
    await bio.enroll(randomBytes(32), "c2FsdA==", "user-42");
    const recovered = await bio.recoverKey();
    expect(recovered!.userId).toBe("user-42");
    expect(recovered!.saltB64).toBe("c2FsdA==");
  });

  it("locking the app zeroes the key VaultApp took ownership of", async () => {
    const { bio } = setup();
    const store = await enrolledVault(bio);
    const recovered = await bio.recoverKey();
    const app = new VaultApp(SALT, store, null, KDF);
    await app.unlockWithKey(recovered!.key);
    app.lock();
    expect(recovered!.key.every((b) => b === 0)).toBe(true);
    expect(() => app.list()).toThrow(/locked/);
  });
});
