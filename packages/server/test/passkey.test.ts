import { describe, it, expect } from "vitest";
import {
  createHash,
  generateKeyPairSync,
  randomBytes,
  sign as cryptoSign,
  type KeyObject,
} from "node:crypto";
import { encodeCbor, type CborValue } from "../src/auth/cbor.js";
import {
  PasskeyService,
  InMemoryPasskeyRepository,
  b64url,
} from "../src/auth/passkey.service.js";

const RP_ID = "localhost";
const ORIGIN = "http://localhost:8787";

function svc(ttlMs?: number) {
  return new PasskeyService(new InMemoryPasskeyRepository(), {
    rpId: RP_ID,
    rpName: "VaultKeep",
    origins: [ORIGIN],
    challengeTtlMs: ttlMs,
  });
}

const sha256 = (d: string | Buffer) => createHash("sha256").update(d).digest();

/**
 * A software authenticator: enough of the WebAuthn data model to produce real
 * create()/get() responses — CBOR attestation objects, COSE keys, and
 * signatures node:crypto can verify. What a browser+platform authenticator
 * would hand the client.
 */
class FakeAuthenticator {
  readonly credentialId = randomBytes(16);
  counter = 0;
  private readonly pub: KeyObject;
  private readonly priv: KeyObject;

  constructor(readonly kind: "p256" | "ed25519" = "p256") {
    const pair =
      kind === "p256"
        ? generateKeyPairSync("ec", { namedCurve: "P-256" })
        : generateKeyPairSync("ed25519");
    this.pub = pair.publicKey;
    this.priv = pair.privateKey;
  }

  private coseKey(): Map<number | string, CborValue> {
    const jwk = this.pub.export({ format: "jwk" }) as Record<string, string>;
    if (this.kind === "p256") {
      return new Map<number | string, CborValue>([
        [1, 2], [3, -7], [-1, 1],
        [-2, new Uint8Array(Buffer.from(jwk.x, "base64url"))],
        [-3, new Uint8Array(Buffer.from(jwk.y, "base64url"))],
      ]);
    }
    return new Map<number | string, CborValue>([
      [1, 1], [3, -8], [-1, 6],
      [-2, new Uint8Array(Buffer.from(jwk.x, "base64url"))],
    ]);
  }

  private authData(rpId: string, withCredential: boolean, counter: number): Buffer {
    const head = Buffer.alloc(37);
    sha256(rpId).copy(head, 0);
    head[32] = withCredential ? 0x41 : 0x01; // UP (+AT when attesting)
    head.writeUInt32BE(counter, 33);
    if (!withCredential) return head;
    const idLen = Buffer.alloc(2);
    idLen.writeUInt16BE(this.credentialId.length);
    return Buffer.concat([
      head,
      Buffer.alloc(16), // aaguid
      idLen,
      this.credentialId,
      Buffer.from(encodeCbor(this.coseKey())),
    ]);
  }

  /** navigator.credentials.create() response for the given options. */
  attest(options: { challenge: string; rp: { id: string } }, origin = ORIGIN, rpId?: string) {
    const clientDataJSON = Buffer.from(
      JSON.stringify({ type: "webauthn.create", challenge: options.challenge, origin })
    );
    const attestationObject = encodeCbor(
      new Map<number | string, CborValue>([
        ["fmt", "none"],
        ["attStmt", new Map()],
        ["authData", new Uint8Array(this.authData(rpId ?? options.rp.id, true, this.counter))],
      ] as [string, CborValue][])
    );
    return {
      clientDataJSON: b64url(clientDataJSON),
      attestationObject: b64url(Buffer.from(attestationObject)),
    };
  }

  /** navigator.credentials.get() response for the given options. */
  assert(
    options: { challenge: string; rpId: string },
    {
      origin = ORIGIN,
      rpId = options.rpId,
      counter = ++this.counter,
      signer = this.priv,
    }: { origin?: string; rpId?: string; counter?: number; signer?: KeyObject } = {}
  ) {
    const clientDataJSON = Buffer.from(
      JSON.stringify({ type: "webauthn.get", challenge: options.challenge, origin })
    );
    const authData = this.authData(rpId, false, counter);
    const signedData = Buffer.concat([authData, sha256(clientDataJSON)]);
    const signature = cryptoSign(this.kind === "ed25519" ? null : "sha256", signedData, signer);
    return {
      credentialId: b64url(this.credentialId),
      clientDataJSON: b64url(clientDataJSON),
      authenticatorData: b64url(authData),
      signature: b64url(signature),
    };
  }
}

async function register(s: PasskeyService, auth: FakeAuthenticator, userId = "u1") {
  const options = await s.registrationOptions(userId, "me@x.com");
  const result = await s.verifyRegistration(userId, auth.attest(options));
  expect(result.ok).toBe(true);
  return options;
}

describe("PasskeyService (browser-native WebAuthn)", () => {
  it("registers a P-256 passkey and accepts a valid assertion", async () => {
    const s = svc();
    const auth = new FakeAuthenticator("p256");
    await register(s, auth);
    expect(await s.hasPasskeys("u1")).toBe(true);

    const options = await s.assertionOptions("u1");
    expect(options.allowCredentials).toEqual([
      { type: "public-key", id: b64url(auth.credentialId) },
    ]);
    const result = await s.verifyAssertion("u1", auth.assert(options));
    expect(result).toEqual({ ok: true });
  });

  it("supports Ed25519 credentials too", async () => {
    const s = svc();
    const auth = new FakeAuthenticator("ed25519");
    await register(s, auth);
    const options = await s.assertionOptions("u1");
    expect(await s.verifyAssertion("u1", auth.assert(options))).toEqual({ ok: true });
  });

  it("rejects a replayed challenge (single-use)", async () => {
    const s = svc();
    const auth = new FakeAuthenticator();
    await register(s, auth);
    const options = await s.assertionOptions("u1");
    const assertion = auth.assert(options);
    expect(await s.verifyAssertion("u1", assertion)).toEqual({ ok: true });
    // Same signed assertion again — the challenge was consumed.
    const replay = await s.verifyAssertion("u1", assertion);
    expect(replay.ok).toBe(false);
    expect(!replay.ok && replay.reason).toMatch(/replayed/);
  });

  it("rejects an assertion from a disallowed origin", async () => {
    const s = svc();
    const auth = new FakeAuthenticator();
    await register(s, auth);
    const options = await s.assertionOptions("u1");
    const result = await s.verifyAssertion(
      "u1",
      auth.assert(options, { origin: "https://evil.example.com" })
    );
    expect(result.ok).toBe(false);
    expect(!result.ok && result.reason).toMatch(/origin/);
  });

  it("rejects an assertion for the wrong rpId", async () => {
    const s = svc();
    const auth = new FakeAuthenticator();
    await register(s, auth);
    const options = await s.assertionOptions("u1");
    const result = await s.verifyAssertion("u1", auth.assert(options, { rpId: "evil.example.com" }));
    expect(result.ok).toBe(false);
    expect(!result.ok && result.reason).toMatch(/rpId/);
  });

  it("rejects an expired challenge", async () => {
    const s = svc(1); // 1 ms TTL
    const auth = new FakeAuthenticator();
    const regOptions = await s.registrationOptions("u1", "me@x.com");
    await new Promise((r) => setTimeout(r, 10));
    const result = await s.verifyRegistration("u1", auth.attest(regOptions));
    expect(result.ok).toBe(false);
    expect(!result.ok && result.reason).toMatch(/expired/);
  });

  it("rejects a forged signature", async () => {
    const s = svc();
    const auth = new FakeAuthenticator();
    await register(s, auth);
    const options = await s.assertionOptions("u1");
    const wrongKey = generateKeyPairSync("ec", { namedCurve: "P-256" }).privateKey;
    const result = await s.verifyAssertion("u1", auth.assert(options, { signer: wrongKey }));
    expect(result.ok).toBe(false);
    expect(!result.ok && result.reason).toMatch(/signature/);
  });

  it("rejects a sign-count regression (cloned authenticator)", async () => {
    const s = svc();
    const auth = new FakeAuthenticator();
    await register(s, auth);

    let options = await s.assertionOptions("u1");
    expect(await s.verifyAssertion("u1", auth.assert(options, { counter: 5 }))).toEqual({ ok: true });

    // A clone re-using an old counter value must be refused.
    options = await s.assertionOptions("u1");
    const result = await s.verifyAssertion("u1", auth.assert(options, { counter: 5 }));
    expect(result.ok).toBe(false);
    expect(!result.ok && result.reason).toMatch(/sign count/);
  });

  it("rejects an assertion with an unregistered credential", async () => {
    const s = svc();
    const auth = new FakeAuthenticator();
    await register(s, auth);
    const stranger = new FakeAuthenticator();
    const options = await s.assertionOptions("u1");
    const result = await s.verifyAssertion("u1", stranger.assert(options));
    expect(result.ok).toBe(false);
    expect(!result.ok && result.reason).toMatch(/unknown credential/);
  });

  it("binds challenges to the user they were minted for", async () => {
    const s = svc();
    const auth = new FakeAuthenticator();
    await register(s, auth, "u1");
    const otherAuth = new FakeAuthenticator();
    await register(s, otherAuth, "u2");

    // u2's challenge presented on u1's account must fail even with u1's key.
    const optionsForU2 = await s.assertionOptions("u2");
    const result = await s.verifyAssertion("u1", auth.assert(optionsForU2));
    expect(result.ok).toBe(false);
  });

  it("rejects a create() payload replayed into the get() ceremony", async () => {
    const s = svc();
    const auth = new FakeAuthenticator();
    await register(s, auth);
    // Mint a registration challenge but present it as an assertion.
    const regOptions = await s.registrationOptions("u1", "me@x.com");
    const forged = auth.assert({ challenge: regOptions.challenge, rpId: RP_ID });
    const result = await s.verifyAssertion("u1", forged);
    expect(result.ok).toBe(false);
  });

  it("refuses to register the same credential twice", async () => {
    const s = svc();
    const auth = new FakeAuthenticator();
    await register(s, auth);
    const options = await s.registrationOptions("u1", "me@x.com");
    const result = await s.verifyRegistration("u1", auth.attest(options));
    expect(result.ok).toBe(false);
    expect(!result.ok && result.reason).toMatch(/already registered/);
  });
});
