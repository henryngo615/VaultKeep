import {
  app,
  BrowserWindow,
  ipcMain,
  safeStorage,
  systemPreferences,
} from "electron";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { readFile, writeFile, mkdir, rm } from "node:fs/promises";
import { homedir } from "node:os";
import { VaultApp } from "../core/vault-app.js";
import { FileStore } from "../core/local-store.js";
import { HttpTransport } from "../core/sync-client.js";
import { AuthClient, type DeviceIdentity, type Session } from "../core/auth-client.js";
import QRCode from "qrcode";
import {
  BiometricUnlock,
  type SecureEnclave,
  type TokenStore,
} from "../core/biometric.js";
import { helloAvailable, helloPrompt } from "./windows-hello.js";
import { vaultHealth, httpRangeClient } from "../core/vault-health.js";
import {
  generateSalt,
  generatePassword,
  generatePassphrase,
} from "@vaultkeep/crypto";

const __dirname = dirname(fileURLToPath(import.meta.url));
const VAULT_DIR = join(homedir(), ".vaultkeep");
const SALT_PATH = join(VAULT_DIR, "salt");
const STORE_PATH = join(VAULT_DIR, "vault.enc");
const BIO_TOKEN_PATH = join(VAULT_DIR, "biometric.token");
const DEVICE_PATH = join(VAULT_DIR, "device.json");
const SERVER_URL = process.env.VK_SERVER ?? "http://localhost:8787";

// The active server session (set after a successful online login).
let session: Session | null = null;

// --- Electron-backed adapters for the tested core interfaces ---------------

/**
 * Touch ID (macOS) / Windows Hello (Windows). safeStorage (Keychain / DPAPI)
 * wraps the key at rest; the platform's biometric prompt gates every unwrap.
 * Available only when BOTH parts exist — a machine without a biometric
 * verifier falls back to the master password, never to a silent unwrap.
 */
const electronEnclave: SecureEnclave = {
  isAvailable: async () => {
    if (!safeStorage.isEncryptionAvailable()) return false;
    if (process.platform === "darwin") return systemPreferences.canPromptTouchID();
    if (process.platform === "win32") return helloAvailable();
    return false;
  },
  promptUser: async (reason) => {
    if (process.platform === "darwin") {
      try {
        await systemPreferences.promptTouchID(reason);
        return true;
      } catch {
        return false;
      }
    }
    if (process.platform === "win32") return helloPrompt(reason);
    return false;
  },
  encrypt: (s) => safeStorage.encryptString(s).toString("base64"),
  decrypt: (c) => safeStorage.decryptString(Buffer.from(c, "base64")),
};

const bioTokenStore: TokenStore = {
  read: async () => {
    try {
      return await readFile(BIO_TOKEN_PATH, "utf8");
    } catch {
      return null;
    }
  },
  write: async (t) => writeFile(BIO_TOKEN_PATH, t),
  clear: async () => {
    await rm(BIO_TOKEN_PATH, { force: true });
  },
};

const biometric = new BiometricUnlock(electronEnclave, bioTokenStore);

let win: BrowserWindow | null = null;
let appCore: VaultApp | null = null;

/**
 * The Electron main process is the ONLY place the master key lives. The
 * renderer (UI) talks to it over IPC and never sees the key or does crypto —
 * a compromised renderer still can't exfiltrate the key.
 */
async function getSalt(): Promise<string> {
  await mkdir(VAULT_DIR, { recursive: true });
  try {
    return await readFile(SALT_PATH, "utf8");
  } catch {
    const salt = generateSalt();
    await writeFile(SALT_PATH, salt);
    return salt;
  }
}

/**
 * Build a VaultApp wired to the on-disk store. If we have an active server
 * session, use its token + account salt so local and remote agree on the key;
 * otherwise run fully offline with a local salt.
 */
async function buildApp(): Promise<VaultApp> {
  const salt = session?.saltB64 ?? (await getSalt());
  const transport =
    session ? new HttpTransport(SERVER_URL, session.token) : null;
  // Scope the on-disk vault PER ACCOUNT so switching accounts never tries to
  // decrypt another account's blob with the wrong key.
  let storePath = STORE_PATH; // local-only default
  if (session) {
    const dir = join(VAULT_DIR, "vaults");
    await mkdir(dir, { recursive: true });
    storePath = join(dir, `${session.userId}.enc`);
  }
  activeContext = { saltB64: salt, userId: session?.userId ?? null };
  const store = new FileStore(storePath, {
    readFile: (p) => readFile(p, "utf8"),
    writeFile: (p, d) => writeFile(p, d),
  });
  return new VaultApp(salt, store, transport, session?.kdf);
}

/** The salt/account the current appCore was built for — what enrolls with the key. */
let activeContext: { saltB64: string; userId: string | null } | null = null;

/** A VaultApp for the vault a wrapped key belongs to (offline, no session). */
async function buildAppFor(userId: string | null, saltB64: string): Promise<VaultApp> {
  const storePath = userId ? join(VAULT_DIR, "vaults", `${userId}.enc`) : STORE_PATH;
  const store = new FileStore(storePath, {
    readFile: (p) => readFile(p, "utf8"),
    writeFile: (p, d) => writeFile(p, d),
  });
  return new VaultApp(saltB64, store, null);
}

async function loadDevice(): Promise<DeviceIdentity | null> {
  try {
    return JSON.parse(await readFile(DEVICE_PATH, "utf8")) as DeviceIdentity;
  } catch {
    return null;
  }
}
async function saveDevice(d: DeviceIdentity): Promise<void> {
  await mkdir(VAULT_DIR, { recursive: true });
  await writeFile(DEVICE_PATH, JSON.stringify(d));
}

function createWindow() {
  win = new BrowserWindow({
    width: 420,
    height: 640,
    webPreferences: {
      preload: join(__dirname, "preload.cjs"),
      contextIsolation: true,
      nodeIntegration: false,
    },
  });
  win.loadFile(join(__dirname, "../renderer/index.html"));
  if (process.env.VK_DEVTOOLS) win.webContents.openDevTools({ mode: "detach" });
}

// --- IPC: the renderer's only capabilities ---------------------------------

/** Offline unlock: derive the key from a local salt, no server involved. */
ipcMain.handle("vault:unlock", async (_e, masterPassword: string) => {
  session = null; // local-only mode
  appCore = await buildApp();
  try {
    await appCore.unlock(masterPassword);
    return { ok: true };
  } catch (e) {
    console.error("[vault:unlock] failed:", e);
    appCore = null;
    return { ok: false, error: "Incorrect master password" };
  }
});

const authClient = new AuthClient(SERVER_URL, fetch as any);

/** Is there a server configured + a device already enrolled? */
ipcMain.handle("account:status", async () => ({
  serverUrl: SERVER_URL,
  enrolled: (await loadDevice()) !== null,
}));

// Remember the userId between register and MFA-confirm within a signup session.
let pendingUserId: string | null = null;

/** Create an account, enroll this device, and return a TOTP QR to scan. */
ipcMain.handle(
  "account:register",
  async (_e, email: string, masterPassword: string) => {
    try {
      const { device, userId, mfa } = await authClient.register(email, masterPassword);
      await saveDevice(device);
      pendingUserId = userId;
      // Render the otpauth URI to a QR PNG data URL for the renderer to show.
      const qr = await QRCode.toDataURL(mfa.otpauthUri, { margin: 1, width: 180 });
      return { ok: true, qr, secret: mfa.secret };
    } catch (e) {
      return { ok: false, error: String((e as Error).message) };
    }
  }
);

/** Confirm TOTP enrollment with a code from the user's authenticator. */
ipcMain.handle("account:confirmMfa", async (_e, code: string) => {
  if (!pendingUserId) return { ok: false, error: "no pending enrollment" };
  const ok = await authClient.confirmMfa(pendingUserId, code);
  return { ok, error: ok ? undefined : "Code didn't match — try the current one." };
});

/** Finalize an online session: unlock the vault and pull from the server. */
async function activateSession(s: Session, masterPassword: string) {
  session = s;
  appCore = await buildApp();
  await appCore.unlock(masterPassword);
  try { await appCore.sync(); } catch { /* offline-tolerant */ }
}

/** Online login with a TOTP code. */
ipcMain.handle(
  "account:login",
  async (_e, email: string, masterPassword: string, mfaCode: string) => {
    const device = await loadDevice();
    if (!device) return { ok: false, error: "No device enrolled — register first." };
    try {
      const { session: s } = await authClient.login(email, masterPassword, device, mfaCode);
      await activateSession(s, masterPassword);
      return { ok: true };
    } catch (e) {
      session = null; appCore = null;
      return { ok: false, error: String((e as Error).message) };
    }
  }
);

/** Passwordless second factor: this device signs a challenge (no code typed). */
ipcMain.handle(
  "account:loginWithDevice",
  async (_e, email: string, masterPassword: string) => {
    const device = await loadDevice();
    if (!device) return { ok: false, error: "No device enrolled — register first." };
    try {
      const { session: s } = await authClient.loginWithDevice(email, masterPassword, device);
      await activateSession(s, masterPassword);
      return { ok: true };
    } catch (e) {
      session = null; appCore = null;
      return { ok: false, error: String((e as Error).message) };
    }
  }
);

// --- Biometric unlock (Touch ID / Windows Hello) ---------------------------

ipcMain.handle("bio:available", async () => ({
  available: await electronEnclave.isAvailable(),
  enrolled: await biometric.isEnrolled(),
  platform: process.platform,
}));

/**
 * Opt in after a successful unlock: wrap a COPY of the live master key (plus
 * the salt/account it belongs to) behind the OS keystore. No password is
 * stored in any form; the copy is zeroed as soon as it's wrapped.
 */
ipcMain.handle("bio:enroll", async () => {
  if (!appCore?.isUnlocked || !activeContext) {
    return { ok: false, error: "unlock the vault first" };
  }
  const key = appCore.snapshotKey();
  try {
    await biometric.enroll(key, activeContext.saltB64, activeContext.userId);
    return { ok: true };
  } catch (e) {
    return { ok: false, error: String((e as Error).message ?? e) };
  } finally {
    key.fill(0);
  }
});

/** Prompt biometrics, unwrap the key, and unlock — no password, no KDF wait. */
ipcMain.handle("bio:unlock", async () => {
  const recovered = await biometric.recoverKey("Unlock VaultKeep");
  if (!recovered) return { ok: false, error: "Biometric unlock unavailable or declined" };
  session = null; // offline unlock of the enrolled vault
  const app = await buildAppFor(recovered.userId, recovered.saltB64);
  try {
    await app.unlockWithKey(recovered.key);
    appCore = app;
    activeContext = { saltB64: recovered.saltB64, userId: recovered.userId };
    return { ok: true };
  } catch {
    // The vault was re-keyed since enrollment — wipe the stale wrapped key.
    recovered.key.fill(0);
    await biometric.unenroll();
    appCore = null;
    return { ok: false, error: "Stored key no longer matches this vault — unlock with your master password and re-enable biometrics" };
  }
});

/** Opt out: wipe the wrapped key from the OS keystore. */
ipcMain.handle("bio:unenroll", async () => {
  await biometric.unenroll();
  return { ok: true };
});

ipcMain.handle("vault:list", async () => appCore?.list() ?? []);

/**
 * Vault health (breached / reused / weak). Passwords are hashed here in the
 * main process; only 5-char hash prefixes go over the network (k-anonymity).
 */
ipcMain.handle("vault:health", async () => {
  if (!appCore?.isUnlocked) return { error: "vault is locked" };
  return vaultHealth(appCore.list(), httpRangeClient(SERVER_URL));
});

ipcMain.handle("vault:add", async (_e, item) => appCore!.add(item));

ipcMain.handle("vault:sync", async () => appCore!.sync());

ipcMain.handle("vault:lock", async () => {
  appCore?.lock();
  appCore = null;
  return { ok: true };
});

ipcMain.handle("gen:password", async (_e, opts) => generatePassword(opts));
ipcMain.handle("gen:passphrase", async (_e, words: number) =>
  generatePassphrase(words)
);

app.whenReady().then(createWindow);
app.on("window-all-closed", () => {
  appCore?.lock();
  if (process.platform !== "darwin") app.quit();
});
