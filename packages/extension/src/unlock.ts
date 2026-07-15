import { deriveMasterKey, deriveAuthVerifier, decryptBlob, zeroKey } from "./vaultcrypto.js";
import { SyncClient } from "./sync.js";
import type { Credential } from "./matcher.js";

/**
 * The full unlock flow, framework-free and unit-testable:
 *
 *   /auth/kdf → Argon2id(masterPassword) → verifier → /auth/login
 *   (enrolling this browser as a device on first use) → TOTP → /vault/items
 *   → AES-GCM decrypt each blob locally.
 *
 * The password and derived key never leave this function: the password is only
 * fed to the KDF/verifier, and the KEY IS ZEROED in `finally` — the caller
 * gets decrypted credentials, never key material.
 */

export interface UnlockRequest {
  email: string;
  password: string;
  code: string; // 6-digit TOTP
  /** Persisted device handle for this email, if this browser has one. */
  deviceId?: string;
}

export type UnlockResult =
  | { ok: true; credentials: Credential[]; deviceId: string; skipped: number }
  | { ok: false; stage: "login" | "device" | "mfa" | "pull"; reason: string };

export async function unlockVault(client: SyncClient, req: UnlockRequest): Promise<UnlockResult> {
  const kdf = await client.kdf(req.email);
  const key = await deriveMasterKey(req.password, kdf.data.kdfSalt, {
    memoryKiB: kdf.data.kdfMemoryKiB,
    iterations: kdf.data.kdfIterations,
    parallelism: kdf.data.kdfParallel,
  });

  try {
    const verifier = await deriveAuthVerifier(key, req.password);

    // First factor. On a fresh browser (no deviceId) a valid verifier gets
    // { userId, needsDevice } back — enroll, then log in properly.
    let deviceId = req.deviceId;
    let login = await client.login(req.email, verifier, deviceId);
    if (login.status === 200 && login.data.needsDevice && login.data.userId) {
      const enrolled = await client.enrollDevice(login.data.userId, "Browser extension");
      if (enrolled.status !== 201) {
        return { ok: false, stage: "device", reason: "could not enroll this browser" };
      }
      deviceId = enrolled.data.device.id;
      login = await client.login(req.email, verifier, deviceId);
    }
    if (login.status !== 200 || !login.data.token) {
      return { ok: false, stage: "login", reason: login.data.error ?? "invalid credentials" };
    }

    const mfa = await client.mfa(login.data.token, req.code);
    if (mfa.status !== 200 || !mfa.data.token) {
      return { ok: false, stage: "mfa", reason: mfa.data.error ?? "invalid code" };
    }

    const pulled = await client.pull(mfa.data.token);
    if (pulled.status !== 200) {
      const reason =
        pulled.status === 403
          ? pulled.data.error === "device not approved"
            ? "this browser is awaiting approval from one of your trusted devices"
            : pulled.data.error ?? "forbidden"
          : pulled.data.error ?? `sync failed (${pulled.status})`;
      return { ok: false, stage: "pull", reason };
    }

    // Decrypt locally. A row that fails GCM verification (tampered, or written
    // by a different account/key) is skipped, never shown as garbage.
    const credentials: Credential[] = [];
    let skipped = 0;
    for (const row of pulled.data.items ?? []) {
      try {
        const item = JSON.parse(await decryptBlob(key, row.ciphertext));
        credentials.push({
          id: row.id,
          title: item.title ?? "Untitled",
          username: item.username,
          password: item.password,
          url: item.url,
        });
      } catch {
        skipped++;
      }
    }
    return { ok: true, credentials, deviceId: deviceId!, skipped };
  } finally {
    zeroKey(key); // never outlives the unlock, wherever we exited from
  }
}
