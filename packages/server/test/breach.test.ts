import { describe, it, expect } from "vitest";
import { writeFileSync, mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  BreachRangeService,
  sha1HexUpper,
  type RangeUpstream,
} from "../src/breach/range.service.js";

describe("BreachRangeService (k-anonymity range queries)", () => {
  it("returns the suffix for a known-breached password's prefix bucket", async () => {
    const svc = new BreachRangeService();
    svc.loadPasswords(["password123", "hunter2"]);
    const hash = sha1HexUpper("password123");
    const body = await svc.range(hash.slice(0, 5));
    const line = body.split("\n").find((l) => l.startsWith(hash.slice(5)));
    expect(line).toBeDefined();
    expect(line).toMatch(/^[0-9A-F]{35}:\d+$/);
  });

  it("responses never contain a full hash — only 35-char suffixes", async () => {
    const svc = new BreachRangeService();
    svc.loadDemoCorpus();
    const hash = sha1HexUpper("123456");
    const body = await svc.range(hash.slice(0, 5));
    expect(body).not.toContain(hash); // prefix is never echoed back
    for (const line of body.split("\n").filter(Boolean)) {
      expect(line.split(":")[0]).toHaveLength(35);
    }
  });

  it("an empty bucket is an empty body, not an error (no oracle)", async () => {
    const svc = new BreachRangeService();
    expect(await svc.range("00000")).toBe("");
  });

  it("rejects malformed prefixes", async () => {
    const svc = new BreachRangeService();
    for (const bad of ["1234", "123456", "GHIJK", "..%2f", ""]) {
      await expect(svc.range(bad)).rejects.toThrow(/invalid prefix/);
    }
  });

  it("loads HIBP-format HASH:COUNT corpus files and plaintext lines", async () => {
    const dir = mkdtempSync(join(tmpdir(), "vk-corpus-"));
    const file = join(dir, "corpus.txt");
    const h = sha1HexUpper("correct horse battery staple");
    writeFileSync(file, `${h}:12345\nplaintext-password\n`);
    const svc = new BreachRangeService();
    expect(svc.loadCorpusFile(file)).toBe(2);

    expect(await svc.range(h.slice(0, 5))).toContain(`${h.slice(5)}:12345`);
    const p = sha1HexUpper("plaintext-password");
    expect(await svc.range(p.slice(0, 5))).toContain(p.slice(5));
  });

  it("merges upstream results and survives upstream failure", async () => {
    const upHash = sha1HexUpper("upstream-only-pw");
    let calls = 0;
    const upstream: RangeUpstream = {
      async fetchRange(prefix) {
        calls++;
        if (prefix === upHash.slice(0, 5)) return `${upHash.slice(5)}:99`;
        throw new Error("upstream down");
      },
    };
    const svc = new BreachRangeService(upstream);
    svc.loadPasswords(["local-pw"]);

    expect(await svc.range(upHash.slice(0, 5))).toContain(`${upHash.slice(5)}:99`);
    // Memoized: a second query for the same prefix doesn't refetch.
    await svc.range(upHash.slice(0, 5));
    expect(calls).toBe(1);

    // Upstream failure still serves local data.
    const localHash = sha1HexUpper("local-pw");
    expect(await svc.range(localHash.slice(0, 5))).toContain(localHash.slice(5));
  });
});
