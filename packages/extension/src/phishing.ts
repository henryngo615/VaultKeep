/**
 * Phishing guard. Before autofilling, compare the page's origin against the
 * origin stored with the credential. A look-alike domain (amaz0n.com vs
 * amazon.com) must NEVER receive an autofilled password.
 */
export function isAutofillSafe(
  storedUrl: string,
  currentOrigin: string
): { safe: boolean; reason?: string } {
  let stored: URL, current: URL;
  try {
    stored = new URL(storedUrl);
    current = new URL(currentOrigin);
  } catch {
    return { safe: false, reason: "unparseable URL" };
  }
  // Exact registrable-domain match required. (Production: use the Public
  // Suffix List to compute eTLD+1 instead of naive hostname compare.)
  if (stored.hostname !== current.hostname) {
    return {
      safe: false,
      reason: `domain mismatch: stored ${stored.hostname}, page ${current.hostname}`,
    };
  }
  if (current.protocol !== "https:") {
    return { safe: false, reason: "page is not HTTPS" };
  }
  return { safe: true };
}
