import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { COMMON_PASSWORDS } from "./common-passwords.js";

/**
 * K-anonymity breach range queries, HIBP-style.
 *
 * The client hashes a password with SHA-1 LOCALLY and sends only the first 5
 * hex characters. We answer with every known-breached hash SUFFIX in that
 * bucket (`SUFFIX:COUNT` lines); the client compares locally. The server
 * learns a 5-char prefix shared by ~16 million possible hashes — nothing that
 * identifies a password — and the route is unauthenticated and cacheable, so
 * responses can't be linked to a user or a vault item.
 *
 * Corpus sources, in priority order:
 *   1. VK_BREACH_CORPUS=<file> — one plaintext password per line (a real
 *      breach corpus), or `HASH:COUNT` lines (pre-hashed, HIBP dump format)
 *   2. VK_HIBP_UPSTREAM=<base url> — proxy misses to the real HIBP range API
 *      (e.g. https://api.pwnedpasswords.com/range), memoized per prefix
 *   3. built-in demo corpus of well-known breached passwords
 */

export interface RangeUpstream {
  /** Fetch `SUFFIX:COUNT` lines for a prefix from an upstream range API. */
  fetchRange(prefix: string): Promise<string>;
}

export function sha1HexUpper(input: string): string {
  return createHash("sha1").update(input, "utf8").digest("hex").toUpperCase();
}

const PREFIX_RE = /^[0-9A-F]{5}$/;

export class BreachRangeService {
  /** prefix -> [suffix, count][] */
  private buckets = new Map<string, Array<[string, number]>>();
  private upstreamCache = new Map<string, string>();

  constructor(private readonly upstream: RangeUpstream | null = null) {}

  /** Load plaintext passwords (count = popularity rank order descending). */
  loadPasswords(passwords: string[]): void {
    passwords.forEach((pw, i) => this.addHash(sha1HexUpper(pw), passwords.length - i));
  }

  /** Load `HASH:COUNT` or plaintext lines from a corpus file. */
  loadCorpusFile(path: string): number {
    const lines = readFileSync(path, "utf8").split(/\r?\n/).filter(Boolean);
    let n = 0;
    for (const line of lines) {
      const m = /^([0-9A-Fa-f]{40}):(\d+)$/.exec(line.trim());
      if (m) this.addHash(m[1].toUpperCase(), Number(m[2]));
      else this.addHash(sha1HexUpper(line), 1);
      n++;
    }
    return n;
  }

  loadDemoCorpus(): void {
    this.loadPasswords(COMMON_PASSWORDS);
  }

  private addHash(hashHex: string, count: number): void {
    const prefix = hashHex.slice(0, 5);
    const bucket = this.buckets.get(prefix) ?? [];
    bucket.push([hashHex.slice(5), count]);
    this.buckets.set(prefix, bucket);
  }

  static isValidPrefix(prefix: string): boolean {
    return PREFIX_RE.test(prefix);
  }

  /**
   * The `SUFFIX:COUNT` body for one prefix. Local corpus and upstream results
   * are merged so a proxy deployment still covers locally-loaded entries.
   */
  async range(prefix: string): Promise<string> {
    if (!BreachRangeService.isValidPrefix(prefix)) throw new Error("invalid prefix");
    const local = (this.buckets.get(prefix) ?? [])
      .map(([suffix, count]) => `${suffix}:${count}`);

    if (this.upstream) {
      let up = this.upstreamCache.get(prefix);
      if (up === undefined) {
        try {
          up = await this.upstream.fetchRange(prefix);
        } catch {
          up = ""; // upstream down -> serve what we have locally
        }
        this.upstreamCache.set(prefix, up);
      }
      const seen = new Set(local.map((l) => l.split(":")[0]));
      for (const line of up.split(/\r?\n/)) {
        const suffix = line.split(":")[0]?.trim().toUpperCase();
        if (suffix && suffix.length === 35 && !seen.has(suffix)) local.push(line.trim());
      }
    }
    return local.sort().join("\n");
  }
}

/** Upstream client for the real HIBP API (or any compatible mirror). */
export function httpUpstream(baseUrl: string): RangeUpstream {
  return {
    async fetchRange(prefix: string): Promise<string> {
      const res = await fetch(`${baseUrl.replace(/\/$/, "")}/${prefix}`, {
        headers: { "user-agent": "VaultKeep-breach-check" },
      });
      if (!res.ok) throw new Error(`upstream ${res.status}`);
      return res.text();
    },
  };
}
