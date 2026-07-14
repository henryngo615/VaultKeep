import { createHash, createPublicKey, randomBytes, verify as cryptoVerify } from "node:crypto";
import { decodeCbor, decodeCborFirst, type CborValue } from "./cbor.js";

/**
 * Browser-native WebAuthn (passkeys): real registration + assertion
 * ceremonies for hardware keys and platform authenticators, replacing nothing —
 * the Ed25519 device challenge–response (webauthn.service.ts) stays for
 * non-browser clients.
 *
 * Scope note: in a zero-knowledge vault the master password still derives the
 * DECRYPTION key client-side, so a passkey can't replace the password. Here it
 * satisfies the MFA step: pre-MFA token in → assertion verified → full token.
 *
 * Verification follows the W3C spec's server checks:
 *   - clientDataJSON: exact type, single-use unexpired challenge, allowed origin
 *   - authenticatorData: rpIdHash === SHA-256(rpId), User-Present flag
 *   - registration ("none" attestation): extract credential id + COSE key
 *   - assertion: signature over authData ‖ SHA-256(clientDataJSON) with the
 *     stored public key; signCount regression → rejected (clone detection)
 */

export interface PasskeyRecord {
  credentialId: string; // base64url
  userId: string;
  /** Public key as a JSON-encoded JWK (EC P-256, Ed25519, or RSA). */
  publicKeyJwk: string;
  /** COSE algorithm: -7 ES256, -8 EdDSA, -257 RS256. */
  alg: number;
  signCount: number;
  name: string;
  createdAt: string;
}

export interface PasskeyRepository {
  listForUser(userId: string): Promise<PasskeyRecord[]>;
  get(credentialId: string): Promise<PasskeyRecord | null>;
  create(rec: PasskeyRecord): Promise<void>;
  updateSignCount(credentialId: string, signCount: number): Promise<void>;
}

export class InMemoryPasskeyRepository implements PasskeyRepository {
  private items = new Map<string, PasskeyRecord>();
  async listForUser(userId: string) {
    return [...this.items.values()].filter((c) => c.userId === userId);
  }
  async get(credentialId: string) {
    return this.items.get(credentialId) ?? null;
  }
  async create(rec: PasskeyRecord) {
    this.items.set(rec.credentialId, { ...rec });
  }
  async updateSignCount(credentialId: string, signCount: number) {
    const c = this.items.get(credentialId);
    if (c) c.signCount = signCount;
  }
}

interface ChallengeRecord {
  userId: string;
  type: "webauthn.create" | "webauthn.get";
  expiresAt: number;
}

export interface PasskeyConfig {
  rpId: string;
  rpName: string;
  /** Origins allowed in clientDataJSON.origin (e.g. http://localhost:8787). */
  origins: string[];
  challengeTtlMs?: number;
}

const SUPPORTED_ALGS = [-7, -8, -257]; // ES256, EdDSA, RS256

export class PasskeyService {
  /** Pending challenges keyed by the challenge itself — deleted on first use. */
  private challenges = new Map<string, ChallengeRecord>();
  private readonly ttl: number;

  constructor(
    private readonly repo: PasskeyRepository,
    private readonly config: PasskeyConfig
  ) {
    this.ttl = config.challengeTtlMs ?? 2 * 60 * 1000;
  }

  /** Options for navigator.credentials.create() — requires a full session. */
  async registrationOptions(userId: string, email: string) {
    const challenge = this.mintChallenge(userId, "webauthn.create");
    const existing = await this.repo.listForUser(userId);
    return {
      challenge,
      rp: { id: this.config.rpId, name: this.config.rpName },
      user: { id: b64url(Buffer.from(userId)), name: email, displayName: email },
      pubKeyCredParams: SUPPORTED_ALGS.map((alg) => ({ type: "public-key", alg })),
      excludeCredentials: existing.map((c) => ({ type: "public-key", id: c.credentialId })),
      authenticatorSelection: { residentKey: "preferred", userVerification: "preferred" },
      attestation: "none",
      timeout: this.ttl,
    };
  }

  /** Verify a create() result and store the credential. */
  async verifyRegistration(
    userId: string,
    input: { clientDataJSON: string; attestationObject: string; name?: string }
  ): Promise<{ ok: true; credentialId: string } | { ok: false; reason: string }> {
    const client = this.checkClientData(input.clientDataJSON, userId, "webauthn.create");
    if (!client.ok) return client;

    let att: CborValue;
    try {
      att = decodeCbor(fromB64url(input.attestationObject));
    } catch {
      return { ok: false, reason: "malformed attestation object" };
    }
    if (!(att instanceof Map)) return { ok: false, reason: "malformed attestation object" };
    const authData = att.get("authData");
    if (!(authData instanceof Uint8Array)) return { ok: false, reason: "missing authData" };

    const parsed = this.checkAuthData(authData, /*requireCredential*/ true);
    if (!parsed.ok) return parsed;
    const { credentialId, coseKey } = parsed;

    if (await this.repo.get(credentialId!)) {
      return { ok: false, reason: "credential already registered" };
    }

    let jwk: Record<string, string>, alg: number;
    try {
      ({ jwk, alg } = coseToJwk(coseKey!));
    } catch (e) {
      return { ok: false, reason: `unsupported credential key: ${(e as Error).message}` };
    }

    await this.repo.create({
      credentialId: credentialId!,
      userId,
      publicKeyJwk: JSON.stringify(jwk),
      alg,
      signCount: parsed.signCount,
      name: input.name ?? "Passkey",
      createdAt: new Date().toISOString(),
    });
    return { ok: true, credentialId: credentialId! };
  }

  /** Options for navigator.credentials.get() during the MFA step. */
  async assertionOptions(userId: string) {
    const creds = await this.repo.listForUser(userId);
    return {
      challenge: this.mintChallenge(userId, "webauthn.get"),
      rpId: this.config.rpId,
      allowCredentials: creds.map((c) => ({ type: "public-key", id: c.credentialId })),
      userVerification: "preferred",
      timeout: this.ttl,
    };
  }

  async hasPasskeys(userId: string): Promise<boolean> {
    return (await this.repo.listForUser(userId)).length > 0;
  }

  /** Verify a get() result. True only for a fresh challenge + valid signature. */
  async verifyAssertion(
    userId: string,
    input: {
      credentialId: string;
      clientDataJSON: string;
      authenticatorData: string;
      signature: string;
    }
  ): Promise<{ ok: true } | { ok: false; reason: string }> {
    const client = this.checkClientData(input.clientDataJSON, userId, "webauthn.get");
    if (!client.ok) return client;

    const cred = await this.repo.get(input.credentialId);
    if (!cred || cred.userId !== userId) return { ok: false, reason: "unknown credential" };

    const authData = fromB64url(input.authenticatorData);
    const parsed = this.checkAuthData(authData, /*requireCredential*/ false);
    if (!parsed.ok) return parsed;

    // Signature covers authenticatorData ‖ SHA-256(clientDataJSON).
    const signedData = Buffer.concat([
      Buffer.from(authData),
      createHash("sha256").update(fromB64url(input.clientDataJSON)).digest(),
    ]);
    const key = createPublicKey({ key: JSON.parse(cred.publicKeyJwk), format: "jwk" });
    const digest = cred.alg === -8 ? null : "sha256"; // Ed25519 signs raw data
    let valid = false;
    try {
      valid = cryptoVerify(digest, signedData, key, fromB64url(input.signature));
    } catch {
      valid = false;
    }
    if (!valid) return { ok: false, reason: "invalid signature" };

    // Clone detection: a counter that goes backwards means a copied key.
    if (parsed.signCount > 0 || cred.signCount > 0) {
      if (parsed.signCount <= cred.signCount) {
        return { ok: false, reason: "sign count regression (possible cloned key)" };
      }
      await this.repo.updateSignCount(cred.credentialId, parsed.signCount);
    }
    return { ok: true };
  }

  // --- ceremony building blocks ------------------------------------------

  private mintChallenge(userId: string, type: ChallengeRecord["type"]): string {
    const challenge = b64url(randomBytes(32));
    this.challenges.set(challenge, { userId, type, expiresAt: Date.now() + this.ttl });
    return challenge;
  }

  /**
   * Validate clientDataJSON: exact ceremony type, our own single-use unexpired
   * challenge bound to this user, and an allowed origin. Consumes the
   * challenge whatever the outcome — a failed attempt can't retry it.
   */
  private checkClientData(
    clientDataB64url: string,
    userId: string,
    expectedType: ChallengeRecord["type"]
  ): { ok: true } | { ok: false; reason: string } {
    let data: { type?: string; challenge?: string; origin?: string };
    try {
      data = JSON.parse(Buffer.from(fromB64url(clientDataB64url)).toString("utf8"));
    } catch {
      return { ok: false, reason: "malformed clientDataJSON" };
    }
    if (data.type !== expectedType) return { ok: false, reason: "wrong ceremony type" };

    const rec = data.challenge ? this.challenges.get(data.challenge) : undefined;
    if (rec) this.challenges.delete(data.challenge!); // single-use, even on failure
    if (!rec || rec.type !== expectedType || rec.userId !== userId) {
      return { ok: false, reason: "unknown or replayed challenge" };
    }
    if (Date.now() > rec.expiresAt) return { ok: false, reason: "challenge expired" };

    if (!data.origin || !this.config.origins.includes(data.origin)) {
      return { ok: false, reason: `origin not allowed: ${data.origin}` };
    }
    return { ok: true };
  }

  /** Validate authenticatorData and optionally extract the new credential. */
  private checkAuthData(
    authData: Uint8Array,
    requireCredential: boolean
  ):
    | { ok: true; signCount: number; credentialId?: string; coseKey?: Map<number | string, CborValue> }
    | { ok: false; reason: string } {
    if (authData.length < 37) return { ok: false, reason: "authData too short" };

    const rpIdHash = Buffer.from(authData.slice(0, 32));
    const expected = createHash("sha256").update(this.config.rpId).digest();
    if (!rpIdHash.equals(expected)) return { ok: false, reason: "rpId mismatch" };

    const flags = authData[32];
    if (!(flags & 0x01)) return { ok: false, reason: "user not present" };

    const signCount =
      (authData[33] << 24) | (authData[34] << 16) | (authData[35] << 8) | authData[36];

    if (!requireCredential) return { ok: true, signCount: signCount >>> 0 };

    if (!(flags & 0x40)) return { ok: false, reason: "no attested credential data" };
    // attestedCredentialData: aaguid(16) ‖ credIdLen(2) ‖ credId ‖ COSE key
    const idLen = (authData[53] << 8) | authData[54];
    const idEnd = 55 + idLen;
    if (authData.length < idEnd) return { ok: false, reason: "authData truncated" };
    const credentialId = b64url(Buffer.from(authData.slice(55, idEnd)));
    const [coseKey] = decodeCborFirst(authData.slice(idEnd));
    if (!(coseKey instanceof Map)) return { ok: false, reason: "malformed COSE key" };
    return { ok: true, signCount: signCount >>> 0, credentialId, coseKey };
  }
}

/** COSE_Key (RFC 9052) → Node-compatible JWK, for the algs we advertise. */
function coseToJwk(cose: Map<number | string, CborValue>): {
  jwk: Record<string, string>;
  alg: number;
} {
  const kty = cose.get(1);
  const alg = cose.get(3);
  if (typeof alg !== "number" || !SUPPORTED_ALGS.includes(alg)) {
    throw new Error(`alg ${String(alg)}`);
  }
  if (kty === 2 && alg === -7) {
    // EC2 / P-256
    if (cose.get(-1) !== 1) throw new Error("EC curve must be P-256");
    const x = cose.get(-2), y = cose.get(-3);
    if (!(x instanceof Uint8Array) || !(y instanceof Uint8Array)) throw new Error("EC coords");
    return { jwk: { kty: "EC", crv: "P-256", x: b64url(Buffer.from(x)), y: b64url(Buffer.from(y)) }, alg };
  }
  if (kty === 1 && alg === -8) {
    // OKP / Ed25519
    if (cose.get(-1) !== 6) throw new Error("OKP curve must be Ed25519");
    const x = cose.get(-2);
    if (!(x instanceof Uint8Array)) throw new Error("OKP x");
    return { jwk: { kty: "OKP", crv: "Ed25519", x: b64url(Buffer.from(x)) }, alg };
  }
  if (kty === 3 && alg === -257) {
    // RSA
    const n = cose.get(-1), e = cose.get(-2);
    if (!(n instanceof Uint8Array) || !(e instanceof Uint8Array)) throw new Error("RSA params");
    return { jwk: { kty: "RSA", n: b64url(Buffer.from(n)), e: b64url(Buffer.from(e)) }, alg };
  }
  throw new Error(`kty ${String(kty)}`);
}

export function b64url(buf: Buffer): string {
  return buf.toString("base64url");
}
export function fromB64url(s: string): Uint8Array {
  return new Uint8Array(Buffer.from(s, "base64url"));
}
