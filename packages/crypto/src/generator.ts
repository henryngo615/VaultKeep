import { randomInt } from "node:crypto";

export interface PasswordOptions {
  length: number; // 8–128
  uppercase: boolean;
  lowercase: boolean;
  numbers: boolean;
  symbols: boolean;
}

const SETS = {
  uppercase: "ABCDEFGHJKLMNPQRSTUVWXYZ", // no I/O — ambiguous
  lowercase: "abcdefghijkmnpqrstuvwxyz", // no l
  numbers: "23456789", // no 0/1
  symbols: "!@#$%^&*-_=+?",
};

/** Cryptographically-random password using rejection-free randInt. */
export function generatePassword(opts: PasswordOptions): string {
  const pool =
    (opts.uppercase ? SETS.uppercase : "") +
    (opts.lowercase ? SETS.lowercase : "") +
    (opts.numbers ? SETS.numbers : "") +
    (opts.symbols ? SETS.symbols : "");
  if (!pool) throw new Error("at least one character set must be enabled");
  const len = Math.min(128, Math.max(8, opts.length));

  let out = "";
  for (let i = 0; i < len; i++) out += pool[randomInt(pool.length)];
  return out;
}

// A small embedded EFF-style word list (truncated; load the full 7776-word
// list in production). Enough to demonstrate the passphrase generator.
const WORDS = [
  "purple", "river", "galaxy", "hammer", "coffee", "shadow", "maple",
  "rocket", "velvet", "candle", "pepper", "orbit", "thunder", "willow",
  "copper", "lantern", "marble", "cactus", "harbor", "comet",
];

export function generatePassphrase(words = 4, separator = "-"): string {
  const parts: string[] = [];
  for (let i = 0; i < words; i++) parts.push(WORDS[randomInt(WORDS.length)]);
  return parts.join(separator);
}
