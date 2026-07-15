/**
 * Thin sync-API client. Mirrors the server routes the web vault and desktop
 * app use; only ciphertext and the derived auth verifier ever cross the wire.
 * `fetch` is injectable so the unlock flow is unit-testable without a server.
 */

export type FetchLike = (input: string, init?: RequestInit) => Promise<Response>;

export interface ApiResult<T = any> {
  status: number;
  data: T;
}

export interface KdfInfo {
  kdfSalt: string;
  kdfMemoryKiB: number;
  kdfIterations: number;
  kdfParallel: number;
}

export interface VaultRow {
  id: string;
  ciphertext: string;
  version: number;
}

export class SyncClient {
  constructor(
    private readonly baseUrl: string,
    private readonly fetchImpl: FetchLike = (...args) => fetch(...args)
  ) {}

  private async call<T>(method: string, path: string, body?: unknown, token?: string): Promise<ApiResult<T>> {
    const res = await this.fetchImpl(this.baseUrl + path, {
      method,
      headers: {
        "content-type": "application/json",
        ...(token ? { authorization: `Bearer ${token}` } : {}),
      },
      body: body === undefined ? undefined : JSON.stringify(body),
    });
    let data: any = {};
    try {
      data = await res.json();
    } catch {
      /* non-JSON response */
    }
    return { status: res.status, data };
  }

  /** Public KDF params for an email (pre-login; decoy for unknown emails). */
  kdf(email: string) {
    return this.call<KdfInfo>("POST", "/auth/kdf", { email });
  }

  /**
   * Exchange the derived verifier for a pre-MFA token. Without a deviceId the
   * server returns `{ userId, needsDevice: true }` on a valid verifier so a
   * fresh client can enroll itself first.
   */
  login(email: string, authVerifier: string, deviceId?: string) {
    return this.call<{ token?: string; userId?: string; needsDevice?: boolean; error?: string }>(
      "POST", "/auth/login", { email, authVerifier, ...(deviceId ? { deviceId } : {}) }
    );
  }

  /** Enroll this browser as a device (first device is auto-approved). */
  enrollDevice(userId: string, name: string) {
    // Placeholder keys, like the web client: this device authenticates with
    // password + TOTP, not device signatures (real keys are the desktop's job).
    const rand = () => {
      const b = new Uint8Array(32);
      crypto.getRandomValues(b);
      return btoa(String.fromCharCode(...b));
    };
    return this.call<{ device: { id: string; approved: boolean } }>(
      "POST", "/devices/enroll",
      { userId, name, platform: "extension", publicKey: rand(), signingPublicKey: rand() }
    );
  }

  /** TOTP step: pre-MFA token + 6-digit code -> full token. */
  mfa(token: string, code: string) {
    return this.call<{ token?: string; error?: string }>("POST", "/auth/mfa", { token, code });
  }

  /** Pull every encrypted item (full token required). */
  pull(token: string) {
    return this.call<{ items?: VaultRow[]; error?: string }>("GET", "/vault/items", undefined, token);
  }
}
