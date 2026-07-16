# VaultKeep Desktop (Mac / Windows)

Electron app. Its main process reuses `@vaultkeep/crypto` for all encryption, so
the same audited zero-knowledge core powers the desktop client.

## Architecture

```
┌─────────────── Electron main process (privileged) ───────────────┐
│  VaultApp  ──uses──▶ @vaultkeep/crypto (Argon2id, AES-256-GCM)    │
│     │                                                             │
│     ├─ FileStore   → ~/.vaultkeep/vault.enc  (encrypted at rest)  │
│     └─ HttpTransport → sync server (ciphertext only)              │
└───────────────────────────▲──────────────────────────────────────┘
                            │ IPC (named channels only)
┌───────────────────────────┴──────────────────────────────────────┐
│  Renderer (sandboxed)  — pure UI, never sees the key              │
└───────────────────────────────────────────────────────────────────┘
```

The renderer runs with `contextIsolation: true`, `nodeIntegration: false`. It can
only call the handful of channels exposed in `preload.ts`. A compromised renderer
cannot read the master key or the filesystem.

## What's implemented + tested (`src/core`)

- `vault-app.ts` — unlock/lock, add/update, two-way `sync()` with conflict
  resolution; all plaintext confined to memory
- `local-store.ts` — `FileStore` encrypts the *entire* vault (including the list
  of which sites you have) as one blob
- `sync-client.ts` — `HttpTransport` to the sync server, behind a `Transport`
  interface so the core is testable in-process

`test/vault-app.test.ts` proves the full stack end-to-end:
- wrong master password is rejected (GCM auth tag)
- items are encrypted at rest — the store contains neither password nor title
- a secret created on one device syncs to another; **server holds only ciphertext**
- a cross-device edit conflict resolves to the server's newer copy

## Run the tests (no Electron needed)

```bash
npm test
```

## Launch the GUI

```bash
npm i -D electron      # ~100 MB, only needed for the GUI
npm start              # builds the shell + opens the window
# optional: point at a running sync server
VK_SERVER=http://localhost:8787 VK_TOKEN=<token> npm start
```

## Biometric unlock (implemented + tested)

`core/biometric.ts` — opt in after a password unlock and a copy of the derived
**master key** (never the password, in any form) is wrapped by the OS keystore
(Keychain on macOS, DPAPI on Windows, via Electron `safeStorage`) together with
the salt/account it belongs to. A later launch prompts **Touch ID** (macOS,
`systemPreferences.promptTouchID`) or **Windows Hello** (a real WinRT
`UserConsentVerifier` prompt driven through PowerShell — no native module) and,
on success, unwraps the key straight into `VaultApp.unlockWithKey()` — no
Argon2 wait. Biometrics are offered only when both the keystore **and** a
biometric verifier exist; otherwise the app falls back to the master password.
Disabling biometrics (🖐️ in the toolbar) wipes the wrapped key; a stale or
tampered wrapped key is rejected by the GCM auth tag and auto-wiped. Adapters
live in `electron/main.ts` + `electron/windows-hello.ts`; the logic is
unit-tested against a mock enclave (`test/biometric.test.ts`, 9 tests, no
Electron required).

## Persistence (closed seam)

`VaultApp` now encrypts its **entire** state into one blob and hands the store an
opaque string, so `FileStore` holds no key and leaks nothing — verified by a
FileStore round-trip test over a fake filesystem.

## Roadmap

- Auto-lock timer, menu-bar quick access
- Per-item conflict prompt (currently last-writer-by-version wins)
