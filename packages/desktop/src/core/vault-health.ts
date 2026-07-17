import { createHash } from "node:crypto";
import type { VaultItem } from "@vaultkeep/shared/types.js";

/**
 * Vault health report: breached / reused / weak passwords.
 *
 * Breach checking is k-anonymity only: the password is SHA-1-hashed LOCALLY
 * and the range client receives just the first 5 hex characters — the
 * interface makes anything else unrepresentable. The returned suffix list is
 * compared here, on the client. The full password and full hash never leave
 * this module (asserted by tests).
 *
 * Reuse and weakness are computed entirely offline; if the range endpoint is
 * unreachable the report still covers those, marking breach status unknown.
 */

/** The ONLY thing the network layer ever sees: a 5-hex-char hash prefix. */
export interface RangeClient {
  range(prefix: string): Promise<string>; // "SUFFIX:COUNT" lines
}

export interface ItemHealth {
  id: string;
  title: string;
  breached: boolean;
  /** How often the password appears in breach corpora (0 = not found). */
  breachCount: number;
  reused: boolean;
  weak: boolean;
  reasons: string[];
}

export interface HealthReport {
  items: ItemHealth[];
  checkedAt: string;
  /** False when the range endpoint couldn't be reached (breach flags unknown). */
  breachCheckAvailable: boolean;
  summary: { total: number; breached: number; reused: number; weak: number };
}

export function sha1HexUpper(input: string): string {
  return createHash("sha1").update(input, "utf8").digest("hex").toUpperCase();
}

/** Conservative strength heuristic — flags what a cracker tries first. */
export function isWeakPassword(pw: string): string | null {
  if (pw.length < 10) return "shorter than 10 characters";
  const classes =
    Number(/[a-z]/.test(pw)) + Number(/[A-Z]/.test(pw)) +
    Number(/[0-9]/.test(pw)) + Number(/[^a-zA-Z0-9]/.test(pw));
  if (pw.length < 14 && classes < 3) return "short and low-variety";
  if (/^(.)\1+$/.test(pw)) return "single repeated character";
  if (/^(?:0123|1234|2345|3456|4567|5678|6789|7890)+/.test(pw) && pw.length < 14) {
    return "sequential digits";
  }
  return null;
}

export async function vaultHealth(
  items: VaultItem[],
  ranges: RangeClient
): Promise<HealthReport> {
  const withPasswords = items.filter((i) => typeof i.password === "string" && i.password.length > 0);

  // Count identical passwords for reuse detection (offline).
  const usage = new Map<string, number>();
  for (const it of withPasswords) {
    usage.set(it.password!, (usage.get(it.password!) ?? 0) + 1);
  }

  // One range query per UNIQUE password, memoized per prefix.
  let breachCheckAvailable = true;
  const prefixCache = new Map<string, Map<string, number>>();
  async function breachCount(pw: string): Promise<number> {
    const hash = sha1HexUpper(pw);
    const prefix = hash.slice(0, 5);
    const suffix = hash.slice(5);
    let bucket = prefixCache.get(prefix);
    if (!bucket) {
      bucket = new Map();
      try {
        for (const line of (await ranges.range(prefix)).split(/\r?\n/)) {
          const [sfx, count] = line.split(":");
          if (sfx) bucket.set(sfx.trim().toUpperCase(), Number(count ?? 0));
        }
      } catch {
        breachCheckAvailable = false;
      }
      prefixCache.set(prefix, bucket);
    }
    return bucket.get(suffix) ?? 0; // the comparison happens HERE, locally
  }

  const out: ItemHealth[] = [];
  for (const it of withPasswords) {
    const pw = it.password!;
    const count = breachCheckAvailable ? await breachCount(pw) : 0;
    const weakReason = isWeakPassword(pw);
    const reused = (usage.get(pw) ?? 0) > 1;
    const reasons: string[] = [];
    if (count > 0) reasons.push(`found in known breaches (${count.toLocaleString()}×)`);
    if (reused) reasons.push("same password used on another item");
    if (weakReason) reasons.push(weakReason);
    out.push({
      id: it.id,
      title: it.title,
      breached: count > 0,
      breachCount: count,
      reused,
      weak: weakReason !== null,
      reasons,
    });
  }

  return {
    items: out,
    checkedAt: new Date().toISOString(),
    breachCheckAvailable,
    summary: {
      total: out.length,
      breached: out.filter((i) => i.breached).length,
      reused: out.filter((i) => i.reused).length,
      weak: out.filter((i) => i.weak).length,
    },
  };
}

/** Range client for the sync server's /range endpoint (or any HIBP mirror). */
export function httpRangeClient(baseUrl: string): RangeClient {
  return {
    async range(prefix: string): Promise<string> {
      const res = await fetch(`${baseUrl.replace(/\/$/, "")}/range/${prefix}`);
      if (!res.ok) throw new Error(`range ${res.status}`);
      return res.text();
    },
  };
}
