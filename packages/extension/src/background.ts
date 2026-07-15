/**
 * Background service worker. Owns the unlocked session and answers autofill
 * requests from content scripts. The content script sends an analyzed form +
 * origin; we run the tested `planFill` and return only the writes.
 *
 * Session storage: chrome.storage.session — memory-only, never written to
 * disk, wiped when the browser closes — holding decrypted credentials with a
 * sliding auto-lock expiry. The master key never reaches any storage: the
 * unlock flow zeroes it the moment the vault is decrypted.
 */
import { matchCredentials } from "./matcher.js";
import { planFill, type AnalyzedForm } from "./autofill.js";
import { SessionStore, type SessionBackend, type SessionData } from "./session.js";
import { SyncClient } from "./sync.js";
import { unlockVault } from "./unlock.js";

const DEFAULT_SERVER = "http://localhost:8787";
const SESSION_KEY = "vk_session";

// chrome.storage.session: in-memory only (never persisted), exactly what an
// MV3 worker needs to survive its own restarts without touching disk.
const chromeSessionBackend: SessionBackend = {
  async get() {
    const bag = await chrome.storage.session.get(SESSION_KEY);
    return (bag[SESSION_KEY] as SessionData | undefined) ?? null;
  },
  async set(data) {
    await chrome.storage.session.set({ [SESSION_KEY]: data });
  },
  async clear() {
    await chrome.storage.session.remove(SESSION_KEY);
  },
};

const session = new SessionStore(chromeSessionBackend);

// Non-secret device handles per email (like the web client's localStorage).
async function loadDeviceId(email: string): Promise<string | undefined> {
  const key = "vk_device_" + email.toLowerCase();
  return (await chrome.storage.local.get(key))[key];
}
async function saveDeviceId(email: string, deviceId: string): Promise<void> {
  await chrome.storage.local.set({ ["vk_device_" + email.toLowerCase()]: deviceId });
}
async function serverUrl(): Promise<string> {
  return (await chrome.storage.local.get("vk_server")).vk_server ?? DEFAULT_SERVER;
}

chrome.runtime.onMessage.addListener((msg, _sender, sendResponse) => {
  if (msg.kind === "session:unlock") {
    (async () => {
      const base = msg.serverUrl || (await serverUrl());
      await chrome.storage.local.set({ vk_server: base });
      const result = await unlockVault(new SyncClient(base), {
        email: msg.email,
        password: msg.password,
        code: msg.code,
        deviceId: await loadDeviceId(msg.email),
      });
      if (!result.ok) return sendResponse({ ok: false, reason: result.reason });
      await saveDeviceId(msg.email, result.deviceId);
      await session.activate(result.credentials);
      sendResponse({ ok: true, count: result.credentials.length, skipped: result.skipped });
    })().catch((e) => sendResponse({ ok: false, reason: String(e?.message ?? e) }));
    return true; // async response
  }

  if (msg.kind === "session:lock") {
    session.lock().then(() => sendResponse({ ok: true }));
    return true;
  }

  if (msg.kind === "session:status") {
    session.status().then(sendResponse);
    return true;
  }

  if (msg.kind === "autofill:request") {
    (async () => {
      const credentials = await session.credentials();
      if (!credentials) return sendResponse({ status: "locked" });
      const { origin, form } = msg as { origin: string; form: AnalyzedForm };
      const matches = matchCredentials(credentials, origin);
      if (matches.length === 0) return sendResponse({ status: "no-match" });
      // Auto-fill the single best match; multiple matches would prompt in the UI.
      await session.touch(); // successful use keeps the session alive
      sendResponse(planFill(form, matches[0].credential, origin));
    })();
    return true;
  }

  if (msg.kind === "save:offer") {
    // Surface a "save password?" prompt via the popup/notification in a full
    // build. Here we just acknowledge.
    sendResponse({ ok: true });
    return true;
  }
});
