import { createHmac, timingSafeEqual } from "node:crypto";

/**
 * Minimal HS256 JWT issue/verify — dependency-free so it's easy to audit and
 * test. Tokens are scoped to a (userId, deviceId) pair and assert whether MFA
 * has been satisfied for this session. A token alone grants nothing until the
 * device is also `approved` (checked in the guard).
 */

export interface TokenClaims {
  sub: string; // userId
  did: string; // deviceId
  mfa: boolean; // has MFA been satisfied this session?
  exp: number; // unix seconds
}

function b64url(buf: Buffer): string {
  return buf
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}
function b64urlJSON(obj: unknown): string {
  return b64url(Buffer.from(JSON.stringify(obj)));
}

export class TokenService {
  constructor(private readonly secret: string) {
    if (!secret || secret.length < 16) {
      throw new Error("JWT secret must be at least 16 chars");
    }
  }

  issue(
    claims: Omit<TokenClaims, "exp">,
    ttlSeconds = 3600
  ): string {
    const header = { alg: "HS256", typ: "JWT" };
    const payload: TokenClaims = {
      ...claims,
      exp: Math.floor(Date.now() / 1000) + ttlSeconds,
    };
    const head = `${b64urlJSON(header)}.${b64urlJSON(payload)}`;
    const sig = b64url(createHmac("sha256", this.secret).update(head).digest());
    return `${head}.${sig}`;
  }

  /** Returns claims if valid+unexpired, else null. Constant-time signature check. */
  verify(token: string): TokenClaims | null {
    const parts = token.split(".");
    if (parts.length !== 3) return null;
    const [h, p, sig] = parts;
    const expected = b64url(
      createHmac("sha256", this.secret).update(`${h}.${p}`).digest()
    );
    const a = Buffer.from(sig);
    const b = Buffer.from(expected);
    if (a.length !== b.length || !timingSafeEqual(a, b)) return null;

    try {
      const claims = JSON.parse(
        Buffer.from(p.replace(/-/g, "+").replace(/_/g, "/"), "base64").toString()
      ) as TokenClaims;
      if (claims.exp < Math.floor(Date.now() / 1000)) return null;
      return claims;
    } catch {
      return null;
    }
  }
}
