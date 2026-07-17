import { describe, it, expect } from "vitest";
import {
  vaultHealth,
  sha1HexUpper,
  isWeakPassword,
  type RangeClient,
} from "../src/core/vault-health.js";
import type { VaultItem } from "@vaultkeep/shared/types.js";

function item(id: string, title: string, password: string): VaultItem {
  return {
    id, title, password,
    type: "login", username: "u", url: "", tags: [], fields: {}, favorite: false,
    createdAt: "2026-01-01T00:00:00Z", updatedAt: "2026-01-01T00:00:00Z",
  } as VaultItem;
}

/** Range client over a tiny corpus that RECORDS every request it sees. */
function fakeRanges(breached: Record<string, number>) {
  const buckets = new Map<string, string[]>();
  for (const [pw, count] of Object.entries(breached)) {
    const h = sha1HexUpper(pw);
    const arr = buckets.get(h.slice(0, 5)) ?? [];
    arr.push(`${h.slice(5)}:${count}`);
    buckets.set(h.slice(0, 5), arr);
  }
  const requests: string[] = [];
  const client: RangeClient = {
    async range(prefix) {
      requests.push(prefix);
      return (buckets.get(prefix) ?? []).join("\n");
    },
  };
  return { client, requests };
}

describe("vaultHealth", () => {
  it("flags breached passwords with their breach count", async () => {
    const { client } = fakeRanges({ password123: 12345 });
    const report = await vaultHealth(
      [item("1", "Old bank", "password123"), item("2", "Safe", "xK9#mQ2$vL8@wN4z")],
      client
    );
    const bank = report.items.find((i) => i.id === "1")!;
    expect(bank.breached).toBe(true);
    expect(bank.breachCount).toBe(12345);
    expect(report.items.find((i) => i.id === "2")!.breached).toBe(false);
    expect(report.summary.breached).toBe(1);
  });

  it("the full password or full hash NEVER leaves the client", async () => {
    const { client, requests } = fakeRanges({ password123: 1 });
    const secret = "password123";
    await vaultHealth([item("1", "A", secret), item("2", "B", "another-secret-9!")], client);

    expect(requests.length).toBeGreaterThan(0);
    for (const sent of requests) {
      expect(sent).toMatch(/^[0-9A-F]{5}$/); // exactly a 5-hex-char prefix
      expect(sha1HexUpper(secret)).not.toBe(sent);
      expect(sent.includes(secret)).toBe(false);
    }
    // Nothing sent ever contains a full 40-char hash or a suffix.
    const everything = requests.join("");
    expect(everything).not.toContain(sha1HexUpper(secret).slice(5));
    expect(everything).not.toContain(sha1HexUpper("another-secret-9!").slice(5));
  });

  it("flags the same password on multiple items as reused", async () => {
    const { client } = fakeRanges({});
    const report = await vaultHealth(
      [
        item("1", "Shop", "same-everywhere-77!A"),
        item("2", "Forum", "same-everywhere-77!A"),
        item("3", "Unique", "totally-different-1!Bx"),
      ],
      client
    );
    expect(report.items.filter((i) => i.reused).map((i) => i.id).sort()).toEqual(["1", "2"]);
    expect(report.summary.reused).toBe(2);
  });

  it("queries each unique password's prefix once (deduped)", async () => {
    const { client, requests } = fakeRanges({});
    await vaultHealth(
      [item("1", "A", "same-everywhere-77!A"), item("2", "B", "same-everywhere-77!A")],
      client
    );
    expect(requests.length).toBe(1);
  });

  it("flags weak passwords with a reason", async () => {
    const { client } = fakeRanges({});
    const report = await vaultHealth([item("1", "Router", "abc123")], client);
    expect(report.items[0].weak).toBe(true);
    expect(report.items[0].reasons.join()).toMatch(/shorter/);
  });

  it("still reports reuse/weakness offline when the range endpoint is down", async () => {
    const down: RangeClient = { range: async () => { throw new Error("offline"); } };
    const report = await vaultHealth(
      [item("1", "A", "same-pw-everywhere"), item("2", "B", "same-pw-everywhere")],
      down
    );
    expect(report.breachCheckAvailable).toBe(false);
    expect(report.summary.reused).toBe(2);
    expect(report.summary.breached).toBe(0); // unknown, not falsely flagged
  });

  it("items without passwords are skipped", async () => {
    const { client } = fakeRanges({});
    const noPw = { ...item("1", "Note", ""), password: undefined } as unknown as VaultItem;
    const report = await vaultHealth([noPw], client);
    expect(report.summary.total).toBe(0);
  });
});

describe("isWeakPassword", () => {
  it("accepts long high-variety passwords", () => {
    expect(isWeakPassword("xK9#mQ2$vL8@wN4z")).toBeNull();
    expect(isWeakPassword("correct-horse-battery-staple")).toBeNull();
  });
  it("rejects short, repeated, sequential, low-variety passwords", () => {
    expect(isWeakPassword("abc123")).toMatch(/shorter/);
    expect(isWeakPassword("aaaaaaaaaaaa")).toBeTruthy();
    expect(isWeakPassword("123412341234")).toMatch(/low-variety|sequential/);
    expect(isWeakPassword("alllowercase")).toMatch(/low-variety/);
  });
});
