import type { IncomingMessage } from "node:http";
import { TokenService, type TokenClaims } from "./token.service.js";

export interface DeviceLookup {
  /** Returns whether the device is approved for this user, or null if unknown. */
  isApproved(userId: string, deviceId: string): Promise<boolean>;
}

export type AuthResult =
  | { ok: true; claims: TokenClaims }
  | { ok: false; status: 401 | 403; message: string };

/**
 * Gate every protected request through three checks, in order:
 *   1. valid, unexpired, untampered token
 *   2. MFA satisfied for this session
 *   3. the device is approved by an already-trusted device
 *
 * Any failure denies access — this is the choke point that makes a stolen token
 * insufficient on its own.
 */
export async function authenticate(
  req: IncomingMessage,
  tokens: TokenService,
  devices: DeviceLookup
): Promise<AuthResult> {
  const header = req.headers["authorization"];
  if (!header?.startsWith("Bearer ")) {
    return { ok: false, status: 401, message: "missing bearer token" };
  }
  const claims = tokens.verify(header.slice("Bearer ".length));
  if (!claims) {
    return { ok: false, status: 401, message: "invalid or expired token" };
  }
  if (!claims.mfa) {
    return { ok: false, status: 403, message: "MFA required" };
  }
  if (!(await devices.isApproved(claims.sub, claims.did))) {
    return { ok: false, status: 403, message: "device not approved" };
  }
  return { ok: true, claims };
}
