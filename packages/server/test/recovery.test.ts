import { describe, it, expect } from "vitest";
import { randomBytes } from "node:crypto";
import {
  RecoveryService,
  InMemoryRecoveryRepository,
  type RecoveryNotifier,
} from "../src/recovery/recovery.service.js";
import { AccountService } from "../src/auth/account.service.js";
import { InMemoryAccountRepository } from "../src/auth/account.repository.js";
import {
  generateRecoveryKey,
  deriveRecoveryParts,
  wrapMasterKey,
  unwrapMasterKey,
  wrapKeyForContact,
  unwrapKeyFromContact,
  generateExchangeKeys,
  generateSigningKeys,
  signMessage,
} from "@vaultkeep/crypto";

const WAIT = 7 * 24 * 60 * 60 * 1000;
const SALT = randomBytes(16).toString("base64");

function harness(startAt = 0) {
  const clock = { t: startAt };
  const repo = new InMemoryRecoveryRepository();
  const events: string[] = [];
  const notifier: RecoveryNotifier = {
    recoveryKeyUsed: (u) => events.push(`used:${u}`),
    emergencyRequested: (_u, c) => events.push(`requested:${c.id}`),
    emergencyDenied: (_u, c) => events.push(`denied:${c.id}`),
    emergencyReleased: (_u, c) => events.push(`released:${c.id}`),
  };
  const svc = new RecoveryService(repo, notifier, WAIT, () => clock.t);
  return { svc, repo, clock, events };
}

describe("recovery key flow (server side)", () => {
  it("verifier round-trip returns the wrapped blob; client unwraps", async () => {
    const { svc, events } = harness();
    const recoveryKey = generateRecoveryKey();
    const masterKey = randomBytes(32);
    const parts = deriveRecoveryParts(recoveryKey, SALT);

    await svc.setup("u1", parts.authVerifier, wrapMasterKey(parts.wrapKey, masterKey));
    expect(await svc.isConfigured("u1")).toBe(true);

    const out = await svc.begin("u1", parts.authVerifier);
    expect(out).not.toBeNull();
    // The server returned ciphertext; only the client-held wrap key opens it.
    expect(unwrapMasterKey(parts.wrapKey, out!.wrappedKey).equals(masterKey)).toBe(true);
    expect(events).toContain("used:u1"); // owner gets notified of every use
  });

  it("a wrong verifier gets nothing", async () => {
    const { svc } = harness();
    const parts = deriveRecoveryParts(generateRecoveryKey(), SALT);
    await svc.setup("u1", parts.authVerifier, "blob");
    const wrong = deriveRecoveryParts(generateRecoveryKey(), SALT);
    expect(await svc.begin("u1", wrong.authVerifier)).toBeNull();
    expect(await svc.begin("nobody", parts.authVerifier)).toBeNull();
  });

  it("the server never stores unwrapped key material or the verifier itself", async () => {
    const { svc, repo } = harness();
    const recoveryKey = generateRecoveryKey();
    const masterKey = randomBytes(32);
    const parts = deriveRecoveryParts(recoveryKey, SALT);
    await svc.setup("u1", parts.authVerifier, wrapMasterKey(parts.wrapKey, masterKey));

    const contact = generateExchangeKeys();
    const sealed = wrapKeyForContact(masterKey, contact.publicKey);
    await svc.addContact({
      userId: "u1",
      contactEmail: "friend@x.com",
      contactSigningPublicKey: generateSigningKeys().publicKey,
      ephemeralPublicKey: sealed.ephemeralPublicKey,
      wrappedKey: sealed.blob,
    });

    const everythingTheServerKnows = repo.dump();
    expect(everythingTheServerKnows).not.toContain(masterKey.toString("base64"));
    expect(everythingTheServerKnows).not.toContain(parts.wrapKey.toString("base64"));
    expect(everythingTheServerKnows).not.toContain(parts.authVerifier); // only its Argon2 hash
    expect(everythingTheServerKnows).not.toContain(recoveryKey.replace(/-/g, ""));
  });

  it("recovery resets the login verifier so the user can sign in again", async () => {
    const accounts = new AccountService(new InMemoryAccountRepository());
    const { userId } = await accounts.register({
      email: "me@x.com", authVerifier: "old-verifier-123456", kdfSalt: SALT,
    });
    await accounts.resetVerifier(userId, "new-verifier-654321");
    expect(await accounts.verifyLogin("me@x.com", "old-verifier-123456")).toBeNull();
    expect(await accounts.verifyLogin("me@x.com", "new-verifier-654321")).toBe(userId);
  });
});

describe("emergency contact state machine", () => {
  async function enrolled(h = harness()) {
    const contactKeys = generateSigningKeys();
    const exchange = generateExchangeKeys();
    const masterKey = randomBytes(32);
    const sealed = wrapKeyForContact(masterKey, exchange.publicKey);
    const rec = await h.svc.addContact({
      userId: "owner",
      contactEmail: "friend@x.com",
      contactSigningPublicKey: contactKeys.publicKey,
      ephemeralPublicKey: sealed.ephemeralPublicKey,
      wrappedKey: sealed.blob,
    });
    return { ...h, rec, contactKeys, exchange, masterKey };
  }

  it("request starts the waiting period and notifies the owner", async () => {
    const h = await enrolled();
    const sig = signMessage(h.contactKeys.privateKey, `emergency-request:${h.rec.id}`);
    const out = await h.svc.requestAccess(h.rec.id, sig);
    expect(Date.parse(out!.unlockAt)).toBe(WAIT);
    expect(h.events).toContain(`requested:${h.rec.id}`);
  });

  it("a forged request signature is refused", async () => {
    const h = await enrolled();
    const forger = generateSigningKeys();
    const sig = signMessage(forger.privateKey, `emergency-request:${h.rec.id}`);
    expect(await h.svc.requestAccess(h.rec.id, sig)).toBeNull();
  });

  it("collect is impossible before the waiting period elapses", async () => {
    const h = await enrolled();
    await h.svc.requestAccess(h.rec.id, signMessage(h.contactKeys.privateKey, `emergency-request:${h.rec.id}`));
    const collectSig = signMessage(h.contactKeys.privateKey, `emergency-collect:${h.rec.id}`);

    h.clock.t = WAIT - 1000; // 1s before the deadline
    const early = await h.svc.collect(h.rec.id, collectSig);
    expect(early && "waitUntil" in early).toBe(true);
    expect(h.events).not.toContain(`released:${h.rec.id}`);
  });

  it("after the waiting period the contact gets the sealed blob and can unwrap it", async () => {
    const h = await enrolled();
    await h.svc.requestAccess(h.rec.id, signMessage(h.contactKeys.privateKey, `emergency-request:${h.rec.id}`));
    h.clock.t = WAIT + 1;
    const out = await h.svc.collect(h.rec.id, signMessage(h.contactKeys.privateKey, `emergency-collect:${h.rec.id}`));
    expect(out && "wrappedKey" in out).toBe(true);
    if (!out || !("wrappedKey" in out)) return;
    const key = unwrapKeyFromContact(h.exchange.privateKey, {
      ephemeralPublicKey: out.ephemeralPublicKey,
      blob: out.wrappedKey,
    });
    expect(key.equals(h.masterKey)).toBe(true);
    expect(h.events).toContain(`released:${h.rec.id}`);
  });

  it("owner denial during the window cancels access — even after the timer", async () => {
    const h = await enrolled();
    await h.svc.requestAccess(h.rec.id, signMessage(h.contactKeys.privateKey, `emergency-request:${h.rec.id}`));
    expect(await h.svc.deny("owner", h.rec.id)).toBe(true);
    expect(h.events).toContain(`denied:${h.rec.id}`);

    h.clock.t = WAIT * 2; // long after the original deadline
    const out = await h.svc.collect(h.rec.id, signMessage(h.contactKeys.privateKey, `emergency-collect:${h.rec.id}`));
    expect(out).toBeNull();
    // And the denied contact cannot simply re-request.
    expect(
      await h.svc.requestAccess(h.rec.id, signMessage(h.contactKeys.privateKey, `emergency-request:${h.rec.id}`))
    ).toBeNull();
  });

  it("someone else's userId cannot deny", async () => {
    const h = await enrolled();
    await h.svc.requestAccess(h.rec.id, signMessage(h.contactKeys.privateKey, `emergency-request:${h.rec.id}`));
    expect(await h.svc.deny("attacker", h.rec.id)).toBe(false);
  });

  it("re-requesting while pending is idempotent (timer not extended)", async () => {
    const h = await enrolled();
    const sig = signMessage(h.contactKeys.privateKey, `emergency-request:${h.rec.id}`);
    const first = await h.svc.requestAccess(h.rec.id, sig);
    h.clock.t = WAIT / 2;
    const second = await h.svc.requestAccess(h.rec.id, sig);
    expect(second!.unlockAt).toBe(first!.unlockAt);
  });

  it("collect without a prior request is refused", async () => {
    const h = await enrolled();
    h.clock.t = WAIT * 2;
    const out = await h.svc.collect(h.rec.id, signMessage(h.contactKeys.privateKey, `emergency-collect:${h.rec.id}`));
    expect(out).toBeNull();
  });
});
