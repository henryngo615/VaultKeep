import { describe, it, expect } from "vitest";
import { WebauthnService } from "../src/auth/webauthn.service.js";
import { DeviceService, InMemoryDeviceRepository } from "../src/devices/device.service.js";
import { generateSigningKeys, generateExchangeKeys, signMessage } from "@vaultkeep/crypto";

async function setup() {
  const devices = new DeviceService(new InMemoryDeviceRepository());
  const webauthn = new WebauthnService(devices);
  const sign = generateSigningKeys();
  const exch = generateExchangeKeys();
  const device = await devices.enroll({
    userId: "u1",
    name: "Mac",
    platform: "macos",
    publicKey: exch.publicKey,
    signingPublicKey: sign.publicKey,
  });
  return { devices, webauthn, sign, device };
}

describe("WebauthnService (device challenge–response)", () => {
  it("verifies a challenge signed by the enrolled device", async () => {
    const { webauthn, sign, device } = await setup();
    const challenge = await webauthn.createChallenge("u1", device.id);
    const signature = signMessage(sign.privateKey, challenge);
    expect(await webauthn.verifyAssertion("u1", device.id, challenge, signature)).toBe(true);
  });

  it("rejects a signature from a different key", async () => {
    const { webauthn, device } = await setup();
    const evil = generateSigningKeys();
    const challenge = await webauthn.createChallenge("u1", device.id);
    const forged = signMessage(evil.privateKey, challenge);
    expect(await webauthn.verifyAssertion("u1", device.id, challenge, forged)).toBe(false);
  });

  it("rejects a replayed (already-used) challenge", async () => {
    const { webauthn, sign, device } = await setup();
    const challenge = await webauthn.createChallenge("u1", device.id);
    const signature = signMessage(sign.privateKey, challenge);
    expect(await webauthn.verifyAssertion("u1", device.id, challenge, signature)).toBe(true);
    // Second use of the same challenge must fail.
    expect(await webauthn.verifyAssertion("u1", device.id, challenge, signature)).toBe(false);
  });

  it("rejects a challenge the server never issued", async () => {
    const { webauthn, sign, device } = await setup();
    await webauthn.createChallenge("u1", device.id);
    const bogus = Buffer.from("attacker-chosen-challenge").toString("base64");
    const signature = signMessage(sign.privateKey, bogus);
    expect(await webauthn.verifyAssertion("u1", device.id, bogus, signature)).toBe(false);
  });

  it("rejects when the device is not approved", async () => {
    const { devices, webauthn, sign } = await setup();
    // Enroll a SECOND device — it starts unapproved.
    const k = generateSigningKeys();
    const e = generateExchangeKeys();
    const d2 = await devices.enroll({
      userId: "u1", name: "iPhone", platform: "ios",
      publicKey: e.publicKey, signingPublicKey: k.publicKey,
    });
    const challenge = await webauthn.createChallenge("u1", d2.id);
    const signature = signMessage(k.privateKey, challenge);
    expect(await webauthn.verifyAssertion("u1", d2.id, challenge, signature)).toBe(false);
  });
});
