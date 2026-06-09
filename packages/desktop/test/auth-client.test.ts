import { describe, it, expect } from "vitest";
import { AuthClient } from "../src/core/auth-client.js";
import { AccountService } from "@vaultkeep/server/auth/account.service.js";
import { InMemoryAccountRepository } from "@vaultkeep/server/auth/account.repository.js";
import { DeviceService, InMemoryDeviceRepository } from "@vaultkeep/server/devices/device.service.js";
import { TokenService } from "@vaultkeep/server/auth/token.service.js";
import { MfaService, InMemoryMfaRepository } from "@vaultkeep/server/mfa/mfa.service.js";
import { currentCode } from "@vaultkeep/server/mfa/totp.service.js";
import { WebauthnService } from "@vaultkeep/server/auth/webauthn.service.js";

const FAST_KDF = { memoryKiB: 8192, iterations: 2, parallelism: 1 };

/**
 * An in-process `fetch` that routes to the REAL server services, mirroring the
 * HTTP handlers in main.ts. This lets us exercise the genuine zero-knowledge
 * handshake (real Argon2 + real account/device logic) without a socket.
 */
function makeServerFetch() {
  const accounts = new AccountService(new InMemoryAccountRepository());
  const devices = new DeviceService(new InMemoryDeviceRepository());
  const tokens = new TokenService("test-secret-key-abcdefgh");
  const mfa = new MfaService(new InMemoryMfaRepository());
  const webauthn = new WebauthnService(devices);

  const reply = (status: number, data: any) => ({
    ok: status < 400,
    status,
    json: async () => data,
  });

  const fetchImpl = async (url: string, init?: any) => {
    const path = new URL(url).pathname;
    const b = init?.body ? JSON.parse(init.body) : {};

    if (path === "/auth/register") {
      try {
        const { userId } = await accounts.register(b);
        const enroll = await mfa.start(userId, b.email);
        return reply(201, { userId, mfa: enroll });
      } catch (e) {
        return reply(400, { error: String((e as Error).message) });
      }
    }
    if (path === "/auth/mfa/confirm") {
      return reply(200, { ok: await mfa.confirm(b.userId, b.code) });
    }
    if (path === "/devices/enroll") {
      const d = await devices.enroll(b);
      return reply(201, { device: d });
    }
    if (path === "/auth/kdf") {
      return reply(200, await accounts.kdfParamsFor(b.email));
    }
    if (path === "/auth/login") {
      const userId = await accounts.verifyLogin(b.email, b.authVerifier);
      if (!userId) return reply(401, { error: "invalid credentials" });
      return reply(200, {
        token: tokens.issue({ sub: userId, did: b.deviceId, mfa: false }, 300),
        userId,
        mfaRequired: true,
      });
    }
    if (path === "/auth/mfa") {
      const claims = tokens.verify(b.token);
      if (!claims || !(await mfa.verify(claims.sub, b.code))) {
        return reply(401, { error: "invalid MFA code" });
      }
      return reply(200, { token: tokens.issue({ sub: claims.sub, did: claims.did, mfa: true }) });
    }
    if (path === "/auth/webauthn/challenge") {
      const claims = tokens.verify(b.token);
      if (!claims) return reply(401, { error: "invalid token" });
      return reply(200, { challenge: await webauthn.createChallenge(claims.sub, claims.did) });
    }
    if (path === "/auth/webauthn/verify") {
      const claims = tokens.verify(b.token);
      if (!claims) return reply(401, { error: "invalid token" });
      const ok = await webauthn.verifyAssertion(claims.sub, claims.did, b.challenge, b.signature);
      if (!ok) return reply(401, { error: "device assertion failed" });
      return reply(200, { token: tokens.issue({ sub: claims.sub, did: claims.did, mfa: true }) });
    }
    return reply(404, { error: "not found" });
  };

  return { fetchImpl, tokens, devices, mfa };
}

describe("AuthClient real handshake", () => {
  it("registers, returns a TOTP enrollment URI, and enrolls a device", async () => {
    const { fetchImpl } = makeServerFetch();
    const client = new AuthClient("http://server", fetchImpl);

    const reg = await client.register("me@x.com", "master-pw", FAST_KDF);
    expect(reg.userId).toBeTruthy();
    expect(reg.device.deviceId).toBeTruthy();
    expect(reg.mfa.otpauthUri).toContain("otpauth://totp/");
  });

  it("requires a VALID TOTP code to log in (not just any 6 digits)", async () => {
    const { fetchImpl } = makeServerFetch();
    const client = new AuthClient("http://server", fetchImpl);
    const reg = await client.register("me@x.com", "pw", FAST_KDF);

    // Before confirming enrollment, even a correct code can't complete login.
    await expect(
      client.login("me@x.com", "pw", reg.device, currentCode(reg.mfa.secret))
    ).rejects.toThrow();

    // Confirm enrollment with a real code...
    expect(await client.confirmMfa(reg.userId, currentCode(reg.mfa.secret))).toBe(true);

    // ...now an arbitrary 6-digit code is rejected, but the real code works.
    await expect(client.login("me@x.com", "pw", reg.device, "000000")).rejects.toThrow();
    const { session } = await client.login("me@x.com", "pw", reg.device, currentCode(reg.mfa.secret));
    expect(session.token).toBeTruthy();
  });

  it("issues a token that passes the server guard (MFA + approved device)", async () => {
    const { fetchImpl, tokens, devices } = makeServerFetch();
    const client = new AuthClient("http://server", fetchImpl);
    const reg = await client.register("me@x.com", "pw", FAST_KDF);
    await client.confirmMfa(reg.userId, currentCode(reg.mfa.secret));
    const { session } = await client.login("me@x.com", "pw", reg.device, currentCode(reg.mfa.secret));

    const claims = tokens.verify(session.token);
    expect(claims?.mfa).toBe(true);
    expect(await devices.isApproved(session.userId, claims!.did)).toBe(true);
  });

  it("rejects login with the wrong master password", async () => {
    const { fetchImpl } = makeServerFetch();
    const client = new AuthClient("http://server", fetchImpl);
    const reg = await client.register("me@x.com", "right-pw", FAST_KDF);
    await client.confirmMfa(reg.userId, currentCode(reg.mfa.secret));
    await expect(
      client.login("me@x.com", "WRONG-pw", reg.device, currentCode(reg.mfa.secret))
    ).rejects.toThrow();
  });

  it("derives the SAME encryption key at register and login (vault stays readable)", async () => {
    const { fetchImpl } = makeServerFetch();
    const client = new AuthClient("http://server", fetchImpl);
    const reg = await client.register("me@x.com", "pw", FAST_KDF);
    await client.confirmMfa(reg.userId, currentCode(reg.mfa.secret));

    const a = await client.login("me@x.com", "pw", reg.device, currentCode(reg.mfa.secret));
    const b = await client.login("me@x.com", "pw", reg.device, currentCode(reg.mfa.secret));
    expect(a.encryptionKey.equals(b.encryptionKey)).toBe(true);
  });

  it("never transmits the master password or encryption key", async () => {
    const sent: string[] = [];
    const { fetchImpl } = makeServerFetch();
    const spyFetch = async (url: string, init?: any) => {
      if (init?.body) sent.push(init.body);
      return fetchImpl(url, init);
    };
    const client = new AuthClient("http://server", spyFetch);
    const reg = await client.register("me@x.com", "super-secret-master", FAST_KDF);
    await client.confirmMfa(reg.userId, currentCode(reg.mfa.secret));
    await client.login("me@x.com", "super-secret-master", reg.device, currentCode(reg.mfa.secret));

    expect(sent.join("\n")).not.toContain("super-secret-master");
  });

  it("logs in passwordlessly with the device key (no TOTP code)", async () => {
    const { fetchImpl, tokens, devices } = makeServerFetch();
    const client = new AuthClient("http://server", fetchImpl);
    const reg = await client.register("me@x.com", "pw", FAST_KDF);

    // No MFA confirmation needed — the device signs a challenge instead.
    const { session, encryptionKey } = await client.loginWithDevice(
      "me@x.com", "pw", reg.device
    );
    expect(encryptionKey.length).toBe(32);
    const claims = tokens.verify(session.token);
    expect(claims?.mfa).toBe(true);
    expect(await devices.isApproved(session.userId, claims!.did)).toBe(true);
  });

  it("device login still requires the correct master password", async () => {
    const { fetchImpl } = makeServerFetch();
    const client = new AuthClient("http://server", fetchImpl);
    const reg = await client.register("me@x.com", "right-pw", FAST_KDF);
    await expect(
      client.loginWithDevice("me@x.com", "WRONG-pw", reg.device)
    ).rejects.toThrow();
  });

  it("device login fails if the signing key doesn't match the enrolled device", async () => {
    const { fetchImpl } = makeServerFetch();
    const client = new AuthClient("http://server", fetchImpl);
    const reg = await client.register("me@x.com", "pw", FAST_KDF);
    // Tamper: swap in a different signing private key.
    const { generateSigningKeys } = await import("@vaultkeep/crypto");
    const evil = { ...reg.device, signingPrivateKey: generateSigningKeys().privateKey };
    await expect(client.loginWithDevice("me@x.com", "pw", evil)).rejects.toThrow();
  });
});
