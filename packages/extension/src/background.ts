/**
 * Background service worker. Holds the (unlocked) vault session and answers
 * autofill requests from content scripts. The content script sends an analyzed
 * form + origin; we run the tested `planFill` and return only the writes.
 *
 * The vault credentials here are decrypted in the worker after the user unlocks
 * via the popup. They are never exposed to page content — only the specific
 * values for a matched, origin-verified credential are sent back.
 */
import { matchCredentials, type Credential } from "./matcher.js";
import { planFill, type AnalyzedForm } from "./autofill.js";

// In a full build this is populated from the unlocked VaultApp (shared core).
// Kept here as the session cache the popup writes into after unlock.
let session: { credentials: Credential[] } | null = null;

chrome.runtime.onMessage.addListener((msg, _sender, sendResponse) => {
  if (msg.kind === "session:set") {
    session = { credentials: msg.credentials };
    sendResponse({ ok: true });
    return true;
  }

  if (msg.kind === "autofill:request") {
    if (!session) return sendResponse({ status: "locked" });
    const { origin, form } = msg as { origin: string; form: AnalyzedForm };
    const matches = matchCredentials(session.credentials, origin);
    if (matches.length === 0) return sendResponse({ status: "no-match" });
    // Auto-fill the single best match; multiple matches would prompt in the UI.
    const plan = planFill(form, matches[0].credential, origin);
    return sendResponse(plan);
  }

  if (msg.kind === "save:offer") {
    // Surface a "save password?" prompt via the popup/notification in a full
    // build. Here we just acknowledge.
    sendResponse({ ok: true });
    return true;
  }
});
