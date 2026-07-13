# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Workflow rules (mandatory)

- **Never push to `main`.** All changes go through a feature branch and a pull request; the user reviews and merges every PR.
- **Only work from GitHub issues.** Tasks are defined as GitHub issues (written together with the user). Do not start implementation work that isn't backed by an issue; reference the issue in the branch name and PR.

## What this is

VaultKeep is a zero-knowledge, cross-platform password manager (security model comparable to 1Password/Bitwarden). The core invariant that every change must preserve: **all encryption happens on the client; the server only ever stores ciphertext.** The server never receives the master password, the derived key, or any plaintext.

## Commands

Requires Node.js 20+. npm workspaces monorepo — run `npm install` once at the root.

```bash
npm test                                   # root: runs crypto, server, desktop, extension suites
npm run build                              # root: tsc build across all workspaces
npm test --workspace=@vaultkeep/server     # one package's suite
npx vitest run test/guard.test.ts          # single test file (run inside the package dir)
npx vitest run -t "rejects tampered"       # single test by name

npm run dev --workspace=@vaultkeep/server  # sync server on http://localhost:8787 (file-backed DB, zero setup)
npm run build:ext --workspace=@vaultkeep/extension   # bundle MV3 extension into dist/ (esbuild)
npm start --workspace=@vaultkeep/desktop   # Electron GUI (needs `npm i -D electron` first)
```

All packages use TypeScript + Vitest. There is no lint setup.

## Architecture

npm workspaces monorepo; all clients share one crypto core:

- `packages/crypto` — the zero-knowledge foundation: Argon2id KDF (`kdf.ts`), AES-256-GCM vault encryption (`vault.ts`, blob format `nonce‖ciphertext‖tag`), X25519/Ed25519 device keys (`devicekeys.ts`), password generator. `unlockVault()` in `index.ts` is the high-level entry clients use.
- `packages/shared` — TypeScript types shared across packages (exported as raw `.ts`, no build).
- `packages/server` — sync + identity server. Plain `node:http` in `src/main.ts` wiring together tested services: `vault/` (encrypted-blob sync with optimistic concurrency via `baseVersion`), `auth/` (zero-knowledge register/login — client sends a derived auth verifier, server stores only an Argon2 hash of it; HS256 tokens; WebAuthn-style challenge–response), `devices/` (enrollment + Ed25519 signature-based approval), `mfa/` (RFC 6238 TOTP). Storage is repository-pattern: a file-backed `store/filedb.ts` for dev, with Prisma/Postgres adapters in `src/prisma/adapters.ts` ready for production swap (`prisma/schema.prisma`). `public/` serves a demo web client.
- `packages/desktop` — Electron app. All key material and plaintext live only in `src/core/vault-app.ts` (`VaultApp`); everything persisted (locally via `local-store.ts` or synced via `sync-client.ts`) is ciphertext. The Electron shell (`src/electron/`) keeps the renderer key-free — the renderer talks to `VaultApp` over IPC only. Core + tests run without Electron installed.
- `packages/extension` — MV3 browser extension. Autofill decisions live in DOM-free, tested modules (`classify.ts` → `matcher.ts` → `autofill.ts` fill planner); `content.ts` only does DOM I/O. The fill planner is the security choke point and re-checks `phishing.ts` (exact-origin + HTTPS) itself — it never trusts the caller.
- `packages/mobile` — Flutter scaffold only, not implemented.

### Security invariants to preserve

- Server-side request guard enforces, in order: valid token → MFA satisfied → device approved. A pre-MFA token or an unapproved device gets 403 on `/vault/*`.
- First enrolled device is auto-approved; later devices require an already-trusted device to sign `approve-device:<id>` with Ed25519 — the server verifies but cannot mint approvals.
- Wrong master password fails unlock via GCM auth-tag rejection (not a stored password check).
- Extension never autofills on non-HTTPS pages or origins that don't exactly match the stored credential.
- Keys are zeroed (`key.fill(0)`) on lock.

The crypto package is the guarantee; stubbed pieces (extension popup, mobile) are the contract. Security-critical properties are proven by tests — when touching crypto, auth, guard, or autofill logic, extend the corresponding test suite.
