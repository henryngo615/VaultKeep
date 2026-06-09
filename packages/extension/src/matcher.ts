import { isAutofillSafe } from "./phishing.js";

/**
 * Credential matching. Given the vault's logins and the page we're on, decide
 * which credentials may be offered — and crucially, NEVER offer one whose stored
 * origin doesn't exactly match the current page (the phishing guard). A
 * look-alike domain gets zero candidates.
 */
export interface Credential {
  id: string;
  title: string;
  username?: string;
  password?: string;
  url?: string;
}

export interface Match {
  credential: Credential;
  /** Higher = better. Exact username-bearing matches rank first. */
  score: number;
}

/**
 * Return credentials safe to autofill on `pageOrigin`, best first. A credential
 * with no URL, or one whose URL fails the phishing/HTTPS check, is excluded.
 */
export function matchCredentials(
  creds: Credential[],
  pageOrigin: string
): Match[] {
  const out: Match[] = [];
  for (const c of creds) {
    if (!c.url) continue;
    const safe = isAutofillSafe(c.url, pageOrigin);
    if (!safe.safe) continue;

    let score = 1;
    if (c.username) score += 1; // prefer complete credentials
    if (c.password) score += 1;
    out.push({ credential: c, score });
  }
  return out.sort((a, b) => b.score - a.score || a.credential.title.localeCompare(b.credential.title));
}
