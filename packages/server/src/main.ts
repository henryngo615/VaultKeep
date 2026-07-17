import { createServer, IncomingMessage, ServerResponse } from "node:http";
import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { dirname, join, normalize, extname } from "node:path";
import { homedir } from "node:os";
import { VaultService } from "./vault/vault.service.js";
import { TokenService } from "./auth/token.service.js";
import { authenticate } from "./auth/guard.js";
import { AccountService } from "./auth/account.service.js";
import { DeviceService } from "./devices/device.service.js";
import { MfaService } from "./mfa/mfa.service.js";
import { WebauthnService } from "./auth/webauthn.service.js";
import { PasskeyService } from "./auth/passkey.service.js";
import { RecoveryService, type RecoveryNotifier } from "./recovery/recovery.service.js";
import {
  FileDb, FileAccountRepository, FileVaultRepository,
  FileDeviceRepository, FileMfaRepository, FilePasskeyRepository,
  FileRecoveryRepository,
} from "./store/filedb.js";
import QRCode from "qrcode";

/**
 * Dependency-free HTTP layer wiring the tested services together. Uses in-memory
 * storage so it runs with zero setup (`npm run dev`). Swap the In-Memory
 * repositories for the Prisma adapters (see ./prisma/*) in production.
 *
 * Real zero-knowledge auth flow:
 *   POST /auth/register          -> create account (server never sees password)
 *   POST /auth/kdf               -> public KDF params for an email (pre-login)
 *   POST /auth/login             -> verify auth verifier -> pre-MFA token
 *   POST /auth/mfa               -> (demo) elevate to full token
 *   POST /devices/enroll         -> register a device (1st auto-approved)
 *   POST /devices/:id/approve    -> approve via a trusted device's signature
 *   GET  /devices                -> list this account's devices
 *
 * Protected by Bearer auth (valid token + MFA + approved device):
 *   GET/PUT/DELETE /vault/items  -> encrypted blob sync
 */

const PORT = Number(process.env.PORT ?? 8787);
const JWT_SECRET = process.env.JWT_SECRET ?? "dev-only-insecure-secret-change-me";
const DB_PATH = process.env.VK_DB ?? join(homedir(), ".vaultkeep-server", "db.json");
const __dirname = dirname(fileURLToPath(import.meta.url));
const PUBLIC_DIR = join(__dirname, "..", "..", "public");

/**
 * Storage selection: Prisma/Postgres when DATABASE_URL is set, otherwise the
 * zero-setup JSON file store. Either way the server only ever stores
 * ciphertext, verifier hashes, and public keys.
 */
async function buildRepositories() {
  if (process.env.DATABASE_URL) {
    const adapters = await import("./prisma/adapters.js");
    // Resolved at runtime so the server still compiles before `prisma generate`.
    const generatedClient = "./generated/prisma/client.js";
    const { PrismaClient } = await import(generatedClient);
    const { PrismaPg } = await import("@prisma/adapter-pg");
    const prisma = new PrismaClient({
      adapter: new PrismaPg({ connectionString: process.env.DATABASE_URL }),
    });
    console.log("Storage: Postgres via Prisma (DATABASE_URL set)");
    return {
      vault: new adapters.PrismaVaultRepository(prisma),
      accounts: new adapters.PrismaAccountRepository(prisma),
      devices: new adapters.PrismaDeviceRepository(prisma),
      mfa: new adapters.PrismaMfaRepository(prisma),
      passkeys: new adapters.PrismaPasskeyRepository(prisma),
      recovery: new adapters.PrismaRecoveryRepository(prisma),
    };
  }
  const db = new FileDb(DB_PATH);
  console.log(`Storage: JSON file at ${DB_PATH} (set DATABASE_URL for Postgres)`);
  return {
    vault: new FileVaultRepository(db),
    accounts: new FileAccountRepository(db),
    devices: new FileDeviceRepository(db),
    mfa: new FileMfaRepository(db),
    passkeys: new FilePasskeyRepository(db),
    recovery: new FileRecoveryRepository(db),
  };
}

const repos = await buildRepositories();
const vault = new VaultService(repos.vault);
const tokens = new TokenService(JWT_SECRET);
const accounts = new AccountService(repos.accounts);
const deviceService = new DeviceService(repos.devices);
const mfa = new MfaService(repos.mfa);
const webauthn = new WebauthnService(deviceService);
// Browser-native WebAuthn (passkeys). rpId/origins are configurable for prod.
const passkeys = new PasskeyService(repos.passkeys, {
  rpId: process.env.WEBAUTHN_RP_ID ?? "localhost",
  rpName: "VaultKeep",
  origins: (process.env.WEBAUTHN_ORIGINS ?? `http://localhost:${PORT}`).split(","),
});

// Recovery notifications: stdout here; wire to email/push in production.
const notifier: RecoveryNotifier = {
  recoveryKeyUsed: (u) => console.log(`[notify] recovery key used for user ${u}`),
  emergencyRequested: (u, c) =>
    console.log(`[notify] EMERGENCY ACCESS requested by ${c.contactEmail} for user ${u} — unlocks ${c.unlockAt}`),
  emergencyDenied: (u, c) => console.log(`[notify] emergency access DENIED for ${c.contactEmail} (user ${u})`),
  emergencyReleased: (u, c) => console.log(`[notify] emergency key RELEASED to ${c.contactEmail} (user ${u})`),
};
const RECOVERY_WAIT_MS = Number(process.env.VK_EMERGENCY_WAIT_MS ?? 7 * 24 * 60 * 60 * 1000);
const recovery = new RecoveryService(repos.recovery, notifier, RECOVERY_WAIT_MS);

const MIME: Record<string, string> = {
  ".html": "text/html", ".js": "text/javascript", ".css": "text/css",
  ".svg": "image/svg+xml", ".png": "image/png", ".ico": "image/x-icon",
  ".json": "application/json",
};

/** Serve a static file from PUBLIC_DIR, with path-traversal protection. */
async function serveStatic(res: ServerResponse, urlPath: string): Promise<boolean> {
  let rel = decodeURIComponent(urlPath.split("?")[0]);
  if (rel === "/") rel = "/index.html";
  // Redirect /app -> /app/ so the page's relative script URLs resolve under
  // /app/ (served at /app they'd hit the root and 401 off the API guard).
  if (rel === "/app") {
    res.writeHead(301, { location: "/app/" }).end();
    return true;
  }
  if (rel === "/app/") rel = "/app/index.html";
  const full = normalize(join(PUBLIC_DIR, rel));
  if (!full.startsWith(PUBLIC_DIR)) { res.writeHead(403).end(); return true; }
  try {
    const buf = await readFile(full);
    res.writeHead(200, {
      "content-type": MIME[extname(full)] ?? "application/octet-stream",
      // Always serve the latest during development — no stale cached UI.
      "cache-control": "no-store, must-revalidate",
    });
    res.end(buf);
    return true;
  } catch {
    return false;
  }
}

function json(res: ServerResponse, status: number, body: unknown) {
  const data = JSON.stringify(body);
  res.writeHead(status, { "content-type": "application/json" });
  res.end(data);
}

async function readBody(req: IncomingMessage): Promise<any> {
  const chunks: Buffer[] = [];
  for await (const c of req) chunks.push(c as Buffer);
  if (!chunks.length) return {};
  try {
    return JSON.parse(Buffer.concat(chunks).toString());
  } catch {
    return {};
  }
}

const server = createServer(async (req, res) => {
  const url = new URL(req.url ?? "/", `http://localhost:${PORT}`);
  const path = url.pathname;

  // Lightweight request log for API routes (helps diagnose auth issues).
  if (/^\/(auth|vault|devices|recovery|emergency)/.test(path)) {
    const origEnd = res.end.bind(res);
    (res as any).end = (...args: any[]) => {
      console.log(`${req.method} ${path} -> ${res.statusCode}`);
      return origEnd(...args);
    };
  }

  // CORS for the web client (same-origin in practice, but explicit is safe).
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Headers", "authorization, content-type");
  res.setHeader("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS");
  if (req.method === "OPTIONS") { res.writeHead(204).end(); return; }

  // Static web UI: serve the landing page (/) and web vault (/app) for GETs
  // that aren't API routes.
  if (req.method === "GET" && !/^\/(auth|vault|devices|recovery|emergency)/.test(path)) {
    if (await serveStatic(res, path)) return;
  }

  // --- Account registration (server never receives the master password) ----
  if (req.method === "POST" && path === "/auth/register") {
    const b = await readBody(req);
    try {
      const { userId } = await accounts.register({
        email: b.email,
        authVerifier: b.authVerifier,
        kdfSalt: b.kdfSalt,
        kdfMemoryKiB: b.kdfMemoryKiB,
        kdfIterations: b.kdfIterations,
        kdfParallel: b.kdfParallel,
      });
      // Auto-start TOTP enrollment so the client can show a QR immediately.
      const enroll = await mfa.start(userId, b.email);
      const qr = await QRCode.toDataURL(enroll.otpauthUri, { margin: 1, width: 200 });
      return json(res, 201, { userId, mfa: { ...enroll, qr } });
    } catch (e) {
      return json(res, 400, { error: String((e as Error).message) });
    }
  }

  // --- Confirm TOTP enrollment (user scanned the QR, enters a code) --------
  if (req.method === "POST" && path === "/auth/mfa/confirm") {
    const b = await readBody(req);
    const ok = await mfa.confirm(b.userId ?? "", b.code ?? "");
    return json(res, ok ? 200 : 400, { ok });
  }

  // --- Public KDF params for an email (client needs these before login) ----
  if (req.method === "POST" && path === "/auth/kdf") {
    const b = await readBody(req);
    return json(res, 200, await accounts.kdfParamsFor(b.email ?? ""));
  }

  // --- Login: verify the client-derived auth verifier ----------------------
  if (req.method === "POST" && path === "/auth/login") {
    const b = await readBody(req);
    const userId = await accounts.verifyLogin(b.email ?? "", b.authVerifier ?? "");
    if (!userId) return json(res, 401, { error: "invalid credentials" });
    // A VERIFIED client with no device yet (fresh browser/extension) gets its
    // userId so it can enroll itself, then log in again. No token is issued.
    if (!b.deviceId) return json(res, 200, { userId, needsDevice: true });
    // Pre-MFA token: mfa:false until a second factor is satisfied.
    const token = tokens.issue({ sub: userId, did: b.deviceId, mfa: false }, 300);
    return json(res, 200, { token, userId, mfaRequired: true });
  }

  // --- MFA step: verify a real TOTP code, then issue a full token ----------
  if (req.method === "POST" && path === "/auth/mfa") {
    const b = await readBody(req);
    const claims = tokens.verify(b.token ?? "");
    if (!claims) return json(res, 401, { error: "invalid token" });
    if (!(await mfa.verify(claims.sub, b.code ?? ""))) {
      return json(res, 401, { error: "invalid MFA code" });
    }
    const full = tokens.issue({ sub: claims.sub, did: claims.did, mfa: true }, 3600);
    return json(res, 200, { token: full });
  }

  // --- Passkey (browser WebAuthn) as the MFA step ---------------------------
  // Options for navigator.credentials.get(): needs a pre-MFA token.
  if (req.method === "POST" && path === "/auth/passkey/mfa/options") {
    const b = await readBody(req);
    const claims = tokens.verify(b.token ?? "");
    if (!claims) return json(res, 401, { error: "invalid token" });
    if (!(await passkeys.hasPasskeys(claims.sub))) {
      return json(res, 404, { error: "no passkeys enrolled" });
    }
    return json(res, 200, { options: await passkeys.assertionOptions(claims.sub) });
  }

  // Verify the assertion -> full token (passkey satisfies MFA).
  if (req.method === "POST" && path === "/auth/passkey/mfa/verify") {
    const b = await readBody(req);
    const claims = tokens.verify(b.token ?? "");
    if (!claims) return json(res, 401, { error: "invalid token" });
    const result = await passkeys.verifyAssertion(claims.sub, {
      credentialId: b.credentialId ?? "",
      clientDataJSON: b.clientDataJSON ?? "",
      authenticatorData: b.authenticatorData ?? "",
      signature: b.signature ?? "",
    });
    if (!result.ok) return json(res, 401, { error: result.reason });
    const full = tokens.issue({ sub: claims.sub, did: claims.did, mfa: true }, 3600);
    return json(res, 200, { token: full });
  }

  // --- Passkey-style device auth: request a challenge to sign --------------
  if (req.method === "POST" && path === "/auth/webauthn/challenge") {
    const b = await readBody(req);
    const claims = tokens.verify(b.token ?? "");
    if (!claims) return json(res, 401, { error: "invalid token" });
    const challenge = await webauthn.createChallenge(claims.sub, claims.did);
    return json(res, 200, { challenge });
  }

  // --- Verify the signed challenge -> full token (passwordless 2nd factor) -
  if (req.method === "POST" && path === "/auth/webauthn/verify") {
    const b = await readBody(req);
    const claims = tokens.verify(b.token ?? "");
    if (!claims) return json(res, 401, { error: "invalid token" });
    const ok = await webauthn.verifyAssertion(
      claims.sub, claims.did, b.challenge ?? "", b.signature ?? ""
    );
    if (!ok) return json(res, 401, { error: "device assertion failed" });
    const full = tokens.issue({ sub: claims.sub, did: claims.did, mfa: true }, 3600);
    return json(res, 200, { token: full });
  }

  // --- Device enrollment: first device auto-approved -----------------------
  if (req.method === "POST" && path === "/devices/enroll") {
    const b = await readBody(req);
    if (!b.userId || !b.publicKey || !b.signingPublicKey) {
      return json(res, 400, { error: "missing device fields" });
    }
    const d = await deviceService.enroll({
      userId: b.userId,
      name: b.name ?? "Unnamed device",
      platform: b.platform ?? "unknown",
      publicKey: b.publicKey,
      signingPublicKey: b.signingPublicKey,
    });
    return json(res, 201, { device: d });
  }

  // --- Device approval: requires a trusted device's signature --------------
  const approveMatch = path.match(/^\/devices\/([\w-]+)\/approve$/);
  if (req.method === "POST" && approveMatch) {
    const b = await readBody(req);
    const result = await deviceService.approve(
      b.userId, b.approverDeviceId, approveMatch[1], b.signature
    );
    return json(res, result.ok ? 200 : 403, result);
  }

  // --- Recovery (pre-auth: the user has LOST their password) ---------------

  // Present the recovery verifier -> get the wrapped master key back.
  // The blob is ciphertext under the wrap half the server never saw.
  if (req.method === "POST" && path === "/recovery/begin") {
    const b = await readBody(req);
    const uid = await accounts.idFor(b.email ?? "");
    const out = uid ? await recovery.begin(uid, b.authVerifier ?? "") : null;
    if (!out) return json(res, 401, { error: "invalid recovery key" });
    return json(res, 200, { ...out, ...(await accounts.kdfParamsFor(b.email)) });
  }

  // Verified recovery key resets the LOGIN verifier (never touches vault
  // ciphertext — re-encryption under a new password is the client's job).
  if (req.method === "POST" && path === "/recovery/complete") {
    const b = await readBody(req);
    const uid = await accounts.idFor(b.email ?? "");
    const ok = uid && (await recovery.begin(uid, b.authVerifier ?? ""));
    if (!ok) return json(res, 401, { error: "invalid recovery key" });
    try {
      await accounts.resetVerifier(uid!, b.newAuthVerifier ?? "");
      return json(res, 200, { ok: true });
    } catch (e) {
      return json(res, 400, { error: String((e as Error).message) });
    }
  }

  // --- Emergency contact (pre-auth: contact proves key control by signing) --

  if (req.method === "POST" && path === "/emergency/request") {
    const b = await readBody(req);
    const out = await recovery.requestAccess(b.contactId ?? "", b.signature ?? "");
    if (!out) return json(res, 403, { error: "request refused" });
    return json(res, 202, out);
  }

  if (req.method === "POST" && path === "/emergency/collect") {
    const b = await readBody(req);
    const out = await recovery.collect(b.contactId ?? "", b.signature ?? "");
    if (!out) return json(res, 403, { error: "collect refused" });
    if ("waitUntil" in out) return json(res, 403, { error: "waiting period active", ...out });
    return json(res, 200, out);
  }

  // --- Everything below requires authentication ----------------------------
  const auth = await authenticate(req, tokens, deviceService);
  if (!auth.ok) return json(res, auth.status, { error: auth.message });
  const userId = auth.claims.sub;

  if (req.method === "GET" && path === "/devices") {
    return json(res, 200, { devices: await deviceService.list(userId) });
  }

  // --- Passkey registration (requires a FULL session: token+MFA+device) ----
  if (req.method === "POST" && path === "/auth/passkey/register/options") {
    const email = (await accounts.emailFor(userId)) ?? "vaultkeep user";
    return json(res, 200, { options: await passkeys.registrationOptions(userId, email) });
  }

  if (req.method === "POST" && path === "/auth/passkey/register/verify") {
    const b = await readBody(req);
    const result = await passkeys.verifyRegistration(userId, {
      clientDataJSON: b.clientDataJSON ?? "",
      attestationObject: b.attestationObject ?? "",
      name: b.name,
    });
    return json(res, result.ok ? 201 : 400, result);
  }

  // --- Recovery management (full session required) --------------------------

  /** Store/rotate the recovery verifier hash + client-wrapped master key. */
  if (req.method === "POST" && path === "/recovery/setup") {
    const b = await readBody(req);
    try {
      await recovery.setup(userId, b.authVerifier ?? "", b.wrappedKey ?? "");
      return json(res, 201, { ok: true });
    } catch (e) {
      return json(res, 400, { error: String((e as Error).message) });
    }
  }

  if (req.method === "GET" && path === "/recovery/status") {
    return json(res, 200, { configured: await recovery.isConfigured(userId) });
  }

  /** Designate an emergency contact (key already sealed to them client-side). */
  if (req.method === "POST" && path === "/emergency/contacts") {
    const b = await readBody(req);
    try {
      const c = await recovery.addContact({
        userId,
        contactEmail: b.contactEmail ?? "",
        contactSigningPublicKey: b.contactSigningPublicKey ?? "",
        ephemeralPublicKey: b.ephemeralPublicKey ?? "",
        wrappedKey: b.wrappedKey ?? "",
      });
      return json(res, 201, { contact: { id: c.id, contactEmail: c.contactEmail, state: c.state } });
    } catch (e) {
      return json(res, 400, { error: String((e as Error).message) });
    }
  }

  if (req.method === "GET" && path === "/emergency/contacts") {
    const contacts = (await recovery.listContacts(userId)).map((c) => ({
      id: c.id, contactEmail: c.contactEmail, state: c.state, unlockAt: c.unlockAt,
    }));
    return json(res, 200, { contacts });
  }

  /** Owner denies a pending emergency request — cancels the timer for good. */
  if (req.method === "POST" && path === "/emergency/deny") {
    const b = await readBody(req);
    const ok = await recovery.deny(userId, b.contactId ?? "");
    return json(res, ok ? 200 : 404, { ok });
  }

  const itemMatch = path.match(/^\/vault\/items\/([\w-]+)$/);

  if (req.method === "GET" && path === "/vault/items") {
    const items = await vault.pull(userId, url.searchParams.get("since") ?? undefined);
    return json(res, 200, { items });
  }

  if (req.method === "PUT" && itemMatch) {
    const body = await readBody(req);
    const result = await vault.push(userId, {
      id: itemMatch[1],
      ciphertext: body.ciphertext,
      baseVersion: body.baseVersion ?? null,
    });
    return json(res, result.status === "conflict" ? 409 : 200, result);
  }

  if (req.method === "DELETE" && itemMatch) {
    await vault.delete(userId, itemMatch[1]);
    return json(res, 204, {});
  }

  json(res, 404, { error: "not found" });
});

server.listen(PORT, () => {
  console.log(`VaultKeep sync server listening on http://localhost:${PORT}`);
  console.log("Zero-knowledge: only encrypted blobs are stored.");
});
