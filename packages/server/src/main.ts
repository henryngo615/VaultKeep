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
import {
  FileDb, FileAccountRepository, FileVaultRepository,
  FileDeviceRepository, FileMfaRepository,
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

// File-backed, zero-knowledge persistence (survives restarts; swap for Prisma in prod).
const db = new FileDb(DB_PATH);
const vault = new VaultService(new FileVaultRepository(db));
const tokens = new TokenService(JWT_SECRET);
const accounts = new AccountService(new FileAccountRepository(db));
const deviceService = new DeviceService(new FileDeviceRepository(db));
const mfa = new MfaService(new FileMfaRepository(db));
const webauthn = new WebauthnService(deviceService);

const MIME: Record<string, string> = {
  ".html": "text/html", ".js": "text/javascript", ".css": "text/css",
  ".svg": "image/svg+xml", ".png": "image/png", ".ico": "image/x-icon",
  ".json": "application/json",
};

/** Serve a static file from PUBLIC_DIR, with path-traversal protection. */
async function serveStatic(res: ServerResponse, urlPath: string): Promise<boolean> {
  let rel = decodeURIComponent(urlPath.split("?")[0]);
  if (rel === "/") rel = "/index.html";
  if (rel === "/app" || rel === "/app/") rel = "/app/index.html";
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
  if (path.startsWith("/auth") || path.startsWith("/vault") || path.startsWith("/devices")) {
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
  if (req.method === "GET" && !path.startsWith("/auth") && !path.startsWith("/vault") && !path.startsWith("/devices")) {
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

  // --- Everything below requires authentication ----------------------------
  const auth = await authenticate(req, tokens, deviceService);
  if (!auth.ok) return json(res, auth.status, { error: auth.message });
  const userId = auth.claims.sub;

  if (req.method === "GET" && path === "/devices") {
    return json(res, 200, { devices: await deviceService.list(userId) });
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
