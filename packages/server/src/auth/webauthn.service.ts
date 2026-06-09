import { randomBytes } from "node:crypto";
import { verifyMessage } from "@vaultkeep/crypto";
import type { DeviceService } from "../devices/device.service.js";

/**
 * Passkey-style device authentication — the FIDO2/WebAuthn security model
 * (public-key challenge–response) implemented with the Ed25519 keypair each
 * device already holds.
 *
 *   1. challenge() → the server mints a random, single-use, short-lived
 *      challenge bound to (userId, deviceId).
 *   2. the device signs that challenge with its PRIVATE signing key (which
 *      never leaves the device).
 *   3. verify() → the server checks the signature against the device's stored
 *      PUBLIC key, that the device is approved, and that the challenge is fresh
 *      and unused.
 *
 * This is phishing-resistant: a signature over one server's challenge is
 * worthless anywhere else, and there's no shared secret to steal. In a browser
 * this maps to navigator.credentials / WebAuthn; here the desktop app drives it
 * with its own device key.
 */

interface ChallengeRecord {
  challenge: string;
  expiresAt: number;
  used: boolean;
}

const TTL_MS = 2 * 60 * 1000; // 2 minutes

export class WebauthnService {
  private store = new Map<string, ChallengeRecord>(); // key: `${userId}:${deviceId}`
  constructor(private readonly devices: DeviceService) {}

  private key(userId: string, deviceId: string) {
    return `${userId}:${deviceId}`;
  }

  /** Issue a fresh challenge for a device to sign. */
  async createChallenge(userId: string, deviceId: string): Promise<string> {
    const challenge = randomBytes(32).toString("base64");
    this.store.set(this.key(userId, deviceId), {
      challenge,
      expiresAt: Date.now() + TTL_MS,
      used: false,
    });
    return challenge;
  }

  /**
   * Verify a signed challenge. Consumes the challenge (single-use) and requires
   * the device to be enrolled + approved. Returns true only on a valid Ed25519
   * signature over the exact challenge we issued.
   */
  async verifyAssertion(
    userId: string,
    deviceId: string,
    challenge: string,
    signatureB64: string
  ): Promise<boolean> {
    const k = this.key(userId, deviceId);
    const rec = this.store.get(k);
    if (!rec) return false;
    // Single-use + freshness + must match the issued challenge exactly.
    if (rec.used || rec.challenge !== challenge || Date.now() > rec.expiresAt) {
      return false;
    }
    rec.used = true; // consume regardless of signature outcome (no replay)

    const device = await this.devices.get(userId, deviceId);
    if (!device || !device.approved) return false;

    return verifyMessage(device.signingPublicKey, challenge, signatureB64);
  }
}
