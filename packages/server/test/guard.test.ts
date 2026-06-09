import { describe, it, expect } from "vitest";
import type { IncomingMessage } from "node:http";
import { authenticate, type DeviceLookup } from "../src/auth/guard.js";
import { TokenService } from "../src/auth/token.service.js";

const tokens = new TokenService("test-secret-key-abcdefgh");
const approveAll: DeviceLookup = { isApproved: async () => true };
const approveNone: DeviceLookup = { isApproved: async () => false };

function reqWith(auth?: string): IncomingMessage {
  return { headers: auth ? { authorization: auth } : {} } as IncomingMessage;
}

describe("authenticate guard", () => {
  it("rejects a request with no token", async () => {
    const r = await authenticate(reqWith(), tokens, approveAll);
    expect(r).toMatchObject({ ok: false, status: 401 });
  });

  it("rejects an invalid token", async () => {
    const r = await authenticate(reqWith("Bearer garbage"), tokens, approveAll);
    expect(r).toMatchObject({ ok: false, status: 401 });
  });

  it("rejects a valid token that has NOT satisfied MFA", async () => {
    const t = tokens.issue({ sub: "u", did: "d", mfa: false });
    const r = await authenticate(reqWith(`Bearer ${t}`), tokens, approveAll);
    expect(r).toMatchObject({ ok: false, status: 403, message: "MFA required" });
  });

  it("rejects a valid+MFA token from an UNAPPROVED device", async () => {
    const t = tokens.issue({ sub: "u", did: "d", mfa: true });
    const r = await authenticate(reqWith(`Bearer ${t}`), tokens, approveNone);
    expect(r).toMatchObject({ ok: false, status: 403, message: "device not approved" });
  });

  it("admits a valid, MFA-satisfied, approved device", async () => {
    const t = tokens.issue({ sub: "user-7", did: "dev-7", mfa: true });
    const r = await authenticate(reqWith(`Bearer ${t}`), tokens, approveAll);
    expect(r.ok).toBe(true);
    if (r.ok) expect(r.claims.sub).toBe("user-7");
  });
});
