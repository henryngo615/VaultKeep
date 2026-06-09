import {
  deriveMasterKey,
  deriveAuthVerifier,
  generateSalt,
  generateExchangeKeys,
  generateSigningKeys,
  signMessage,
  type KdfParams,
} from "@vaultkeep/crypto";

/**
 * Client side of the zero-knowledge auth handshake. The master password and the
 * derived encryption key NEVER leave this process — only the salt (public) and
 * the one-way auth verifier are sent to the server.
 *
 * `fetchImpl` is injectable so this is testable against the real server logic
 * without a network socket.
 */

type Fetch = (
  url: string,
  init?: { method?: string; headers?: Record<string, string>; body?: string }
) => Promise<{ ok: boolean; status: number; json(): Promise<any> }>;

export interface DeviceIdentity {
  deviceId: string;
  signingPrivateKey: string; // kept locally; used to approve future devices
}

export interface Session {
  token: string; // full (post-MFA) bearer token
  userId: string;
  saltB64: string; // the account's KDF salt, for VaultApp
  kdf: KdfParams;
}

export class AuthClient {
  constructor(
    private readonly baseUrl: string,
    private readonly fetchImpl: Fetch
  ) {}

  private async post(path: string, body: unknown): Promise<{ status: number; data: any }> {
    const res = await this.fetchImpl(`${this.baseUrl}${path}`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(body),
    });
    return { status: res.status, data: await res.json() };
  }

  /**
   * Create an account and enroll this device. Generates a fresh salt + device
   * keys locally. Returns the new userId and the device identity to persist.
   */
  async register(
    email: string,
    masterPassword: string,
    kdf?: KdfParams
  ): Promise<{
    userId: string;
    device: DeviceIdentity;
    saltB64: string;
    mfa: { secret: string; otpauthUri: string };
  }> {
    const saltB64 = generateSalt();
    const key = await deriveMasterKey(masterPassword, saltB64, kdf);
    const authVerifier = deriveAuthVerifier(key, masterPassword);
    key.fill(0); // we only needed it to derive the verifier here

    const reg = await this.post("/auth/register", {
      email,
      authVerifier,
      kdfSalt: saltB64,
      kdfMemoryKiB: kdf?.memoryKiB,
      kdfIterations: kdf?.iterations,
      kdfParallel: kdf?.parallelism,
    });
    if (reg.status !== 201) throw new Error(reg.data.error ?? "registration failed");
    const userId = reg.data.userId as string;

    const exch = generateExchangeKeys();
    const sign = generateSigningKeys();
    const enroll = await this.post("/devices/enroll", {
      userId,
      name: deviceName(),
      platform: process.platform,
      publicKey: exch.publicKey,
      signingPublicKey: sign.publicKey,
    });
    if (enroll.status !== 201) throw new Error("device enrollment failed");

    return {
      userId,
      saltB64,
      device: { deviceId: enroll.data.device.id, signingPrivateKey: sign.privateKey },
      mfa: reg.data.mfa, // { secret, otpauthUri } — show as a QR for the authenticator
    };
  }

  /** Confirm TOTP enrollment with a code from the user's authenticator app. */
  async confirmMfa(userId: string, code: string): Promise<boolean> {
    const r = await this.post("/auth/mfa/confirm", { userId, code });
    return r.status === 200 && r.data.ok === true;
  }

  /**
   * Full login: fetch KDF params, derive the verifier, authenticate, satisfy
   * MFA, and return a usable session (token + salt + kdf) plus the derived
   * encryption key for the vault. `mfaCode` would come from the user's
   * authenticator; the demo server accepts any 6-digit code.
   */
  async login(
    email: string,
    masterPassword: string,
    device: DeviceIdentity,
    mfaCode: string
  ): Promise<{ session: Session; encryptionKey: Buffer }> {
    const pre = await this.password(email, masterPassword, device);
    // Second factor: TOTP code.
    const mfa = await this.post("/auth/mfa", { token: pre.preToken, code: mfaCode });
    if (mfa.status !== 200) {
      pre.encryptionKey.fill(0);
      throw new Error(mfa.data.error ?? "MFA failed");
    }
    return this.finish(pre, mfa.data.token);
  }

  /**
   * Passwordless second factor: instead of a TOTP code, this device proves its
   * identity by signing a server challenge with its Ed25519 key (the WebAuthn /
   * passkey model). Phishing-resistant — no shared secret, no code to type.
   */
  async loginWithDevice(
    email: string,
    masterPassword: string,
    device: DeviceIdentity
  ): Promise<{ session: Session; encryptionKey: Buffer }> {
    const pre = await this.password(email, masterPassword, device);

    // 1. Ask the server for a challenge.
    const ch = await this.post("/auth/webauthn/challenge", { token: pre.preToken });
    if (ch.status !== 200) {
      pre.encryptionKey.fill(0);
      throw new Error(ch.data.error ?? "challenge failed");
    }
    // 2. Sign it with the device's private key (never leaves the device).
    const signature = signMessage(device.signingPrivateKey, ch.data.challenge);
    // 3. Send the assertion.
    const v = await this.post("/auth/webauthn/verify", {
      token: pre.preToken,
      challenge: ch.data.challenge,
      signature,
    });
    if (v.status !== 200) {
      pre.encryptionKey.fill(0);
      throw new Error(v.data.error ?? "device assertion failed");
    }
    return this.finish(pre, v.data.token);
  }

  // --- shared first half of login (KDF + verifier + pre-MFA token) ---------

  private async password(email: string, masterPassword: string, device: DeviceIdentity) {
    const kdfRes = await this.post("/auth/kdf", { email });
    const saltB64 = kdfRes.data.kdfSalt as string;
    const kdf: KdfParams = {
      memoryKiB: kdfRes.data.kdfMemoryKiB,
      iterations: kdfRes.data.kdfIterations,
      parallelism: kdfRes.data.kdfParallel,
    };
    const encryptionKey = await deriveMasterKey(masterPassword, saltB64, kdf);
    const authVerifier = deriveAuthVerifier(encryptionKey, masterPassword);

    const login = await this.post("/auth/login", {
      email,
      authVerifier,
      deviceId: device.deviceId,
    });
    if (login.status !== 200) {
      encryptionKey.fill(0);
      throw new Error(login.data.error ?? "invalid credentials");
    }
    return { encryptionKey, saltB64, kdf, userId: login.data.userId, preToken: login.data.token };
  }

  private finish(
    pre: { encryptionKey: Buffer; saltB64: string; kdf: KdfParams; userId: string },
    fullToken: string
  ): { session: Session; encryptionKey: Buffer } {
    return {
      session: { token: fullToken, userId: pre.userId, saltB64: pre.saltB64, kdf: pre.kdf },
      encryptionKey: pre.encryptionKey,
    };
  }
}

function deviceName(): string {
  const platform = process.platform === "darwin" ? "Mac" : process.platform;
  return `VaultKeep on ${platform}`;
}
