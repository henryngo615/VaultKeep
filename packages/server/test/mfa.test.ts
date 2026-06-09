import { describe, it, expect } from "vitest";
import { MfaService, InMemoryMfaRepository } from "../src/mfa/mfa.service.js";
import { currentCode } from "../src/mfa/totp.service.js";

function svc() {
  return new MfaService(new InMemoryMfaRepository());
}

describe("MfaService (TOTP enrollment + verification)", () => {
  it("starts enrollment and returns an otpauth URI", async () => {
    const m = svc();
    const { secret, otpauthUri } = await m.start("u1", "me@x.com");
    expect(secret).toMatch(/^[A-Z2-7]+$/); // base32
    expect(otpauthUri).toContain("otpauth://totp/");
    expect(otpauthUri).toContain(secret);
  });

  it("is not enrolled until a code confirms the pending secret", async () => {
    const m = svc();
    const { secret } = await m.start("u1", "me@x.com");
    expect(await m.isEnrolled("u1")).toBe(false);
    expect(await m.confirm("u1", currentCode(secret))).toBe(true);
    expect(await m.isEnrolled("u1")).toBe(true);
  });

  it("rejects a wrong confirmation code", async () => {
    const m = svc();
    const { secret } = await m.start("u1", "me@x.com");
    const wrong = currentCode(secret) === "000000" ? "111111" : "000000";
    expect(await m.confirm("u1", wrong)).toBe(false);
    expect(await m.isEnrolled("u1")).toBe(false);
  });

  it("verifies login codes only after confirmation", async () => {
    const m = svc();
    const { secret } = await m.start("u1", "me@x.com");
    // Before confirmation, even a valid code must not verify for login.
    expect(await m.verify("u1", currentCode(secret))).toBe(false);
    await m.confirm("u1", currentCode(secret));
    expect(await m.verify("u1", currentCode(secret))).toBe(true);
  });

  it("rejects verification for an unknown user", async () => {
    const m = svc();
    expect(await m.verify("ghost", "123456")).toBe(false);
  });

  it("rejects a wrong login code", async () => {
    const m = svc();
    const { secret } = await m.start("u1", "me@x.com");
    await m.confirm("u1", currentCode(secret));
    const wrong = currentCode(secret) === "999999" ? "000000" : "999999";
    expect(await m.verify("u1", wrong)).toBe(false);
  });
});
