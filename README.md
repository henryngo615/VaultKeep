# VaultKeep

A zero-knowledge, cross-platform password manager — architecture and working
cryptographic core. Aiming for a security model comparable to 1Password /
Bitwarden: **all encryption happens on the client; the server stores only
ciphertext.**

## Architecture

```
                    ┌─────────────────┐
                    │ Identity Server │  MFA / device approval
                    └────────┬────────┘
                    ┌────────▼────────┐
                    │ Sync API Server │  stores ENCRYPTED blobs only
                    └────────┬────────┘
        ┌──────────────┬─────┴──────┬──────────────┐
   ┌────▼────┐   ┌─────▼────┐  ┌────▼────┐   ┌──────▼──────┐
   │ Mobile  │   │ Desktop  │  │ Desktop │   │  Browser    │
   │ iOS/And │   │ macOS    │  │ Windows │   │  Extension  │
   └─────────┘   └──────────┘  └─────────┘   └─────────────┘
        └──────────── all share @vaultkeep/crypto ───────────┘
```

## Security model

```
Master Password ──Argon2id(256MiB,t=4,p=4)──▶ 256-bit key
                                                  │
                          AES-256-GCM ◀───────────┘
                                                  │
                              encrypted vault item (nonce‖ct‖tag)
```

- **Zero-knowledge**: the server never receives the master password, the
  derived key, or any plaintext.
- **Per-device keys**: X25519 for key exchange, Ed25519 for signing device
  approvals. Private keys never leave the device.
- **Authenticated encryption**: AES-256-GCM — tampering is detected on decrypt.
- **MFA**: TOTP (RFC 6238, implemented), WebAuthn/FIDO2 hardware keys, SMS for
  recovery alerts only.

## Monorepo layout

| Package | What it is | Status |
|---|---|---|
| `packages/crypto` | KDF, AES-256-GCM, device keys, generator | ✅ **implemented + tested** |
| `packages/shared` | Shared TypeScript types | ✅ implemented |
| `packages/server` | Sync API, zero-knowledge auth, devices, TOTP, Prisma adapters | ✅ **implemented + tested** (in-memory store; Prisma adapters ready for the prod swap) |
| `packages/extension` | MV3 browser extension | ✅ **autofill engine implemented + tested**; popup/session UI stubbed |
| `packages/desktop` | Electron desktop (Mac/Win) | ✅ **app core implemented + tested**; Electron GUI shell included |
| `packages/mobile` | Flutter mobile (iOS/Android) | ⬜ scaffold |

## What actually runs today

The cryptographic core is real, dependency-light, and covered by tests:

```bash
# Requires Node.js 20+ (not installed on the build machine — install first)
cd packages/crypto
npm install
npm test
```

The suite proves the security-critical properties:
- Argon2id derives a stable 32-byte key; different salts → different keys
- AES-256-GCM round-trips, uses a fresh random nonce each time
- **tampered ciphertext is rejected** (auth-tag verification)
- wrong key fails to decrypt
- two devices derive the same X25519 shared secret
- Ed25519 verifies valid signatures and rejects forged ones

## Running the sync server

```bash
cd packages/server
npm install
npm test       # 51 tests: sync, JWT, guard, TOTP, accounts, device trust,
               # plus an integration suite against a real (embedded) Postgres
npm run dev    # boots http://localhost:8787 (file-backed, zero setup)
```

To run on Postgres instead of the JSON file store:

```bash
docker compose up -d                 # in packages/server
export DATABASE_URL=postgresql://vaultkeep:vaultkeep@localhost:5432/vaultkeep
npm run db:generate && npm run db:migrate
npm run dev
```

Real zero-knowledge auth flow (the server never receives the master password):

```bash
# 1. register — client sends a DERIVED auth verifier, not the password
USER=$(curl -s -X POST localhost:8787/auth/register \
  -d '{"email":"me@x.com","authVerifier":"<client-derived>","kdfSalt":"<b64>"}' | jq -r .userId)

# 2. enroll a device (first device is auto-approved)
DEV=$(curl -s -X POST localhost:8787/devices/enroll \
  -d "{\"userId\":\"$USER\",\"name\":\"Mac\",\"platform\":\"macos\",\"publicKey\":\"..\",\"signingPublicKey\":\"..\"}" | jq -r .device.id)

# 3. login -> PRE-MFA token (mfa:false)
PRE=$(curl -s -X POST localhost:8787/auth/login \
  -d "{\"email\":\"me@x.com\",\"authVerifier\":\"<client-derived>\",\"deviceId\":\"$DEV\"}" | jq -r .token)

# 4. complete MFA -> FULL token
TOKEN=$(curl -s -X POST localhost:8787/auth/mfa -d "{\"token\":\"$PRE\",\"code\":\"123456\"}" | jq -r .token)

# 5. sync encrypted blobs
curl -X PUT localhost:8787/vault/items/item-1 -H "Authorization: Bearer $TOKEN" \
  -d '{"ciphertext":"<base64 blob>","baseVersion":null}'   # -> {"status":"ok","version":1}
```

The guard enforces three invariants in order: **valid token → MFA satisfied →
device approved**. A pre-MFA token gets 403 on the vault; a stolen full token
from an unapproved device gets 403 too. Verified live end-to-end.

A second device starts UNAPPROVED and can only be approved by an already-trusted
device signing `approve-device:<id>` with its Ed25519 key — the server verifies
that signature and cannot mint approvals itself.

## Roadmap (in dependency order)

1. ✅ Crypto core
2. ✅ Sync server: optimistic-concurrency engine, HS256 device tokens,
   MFA-and-approval guard, RFC 6238 TOTP, **zero-knowledge register/login**
   (server stores only an Argon2 hash of a client-derived verifier — never the
   master password), **device enrollment + signature-based approval** (first
   device auto-trusted; later devices need a trusted device's Ed25519
   signature), **real TOTP MFA** (two-phase enrollment with QR + server-side
   RFC 6238 verification — a wrong code is rejected, not just any 6 digits),
   **passkey-style device auth** (FIDO2/WebAuthn challenge–response: the server
   issues a single-use challenge, the device signs it with its Ed25519 key, the
   server verifies — phishing-resistant, enables passwordless "sign in with this
   device"), **Prisma/Postgres storage** for all repositories — set
   `DATABASE_URL` and the server runs on Postgres (committed migration,
   docker-compose for dev, integration tests against a real embedded Postgres),
   and **browser-native WebAuthn passkeys** (dependency-free CBOR/COSE
   ceremonies: origin + rpId validation, single-use expiring challenges,
   sign-count clone detection; the web vault registers a platform passkey with
   `navigator.credentials.create()` and uses it as the MFA step — verified in a
   real browser with a virtual authenticator).
3. ✅ Desktop app core (Electron): master-password unlock, encrypted-at-rest
   local vault, two-way sync with conflict handling, password generator. The
   GUI shell (main/preload/renderer) is wired over IPC so the renderer never
   touches the key. **Next:** Touch ID / Windows Hello unlock, then mobile.
4. ✅ Browser extension autofill engine: field classifier, origin-scoped
   matcher, and a fill planner that refuses to write passwords on look-alike
   domains or non-HTTPS pages. **Next:** popup unlock wired to crypto/sync,
   passkey support
5. ⬜ Recovery (recovery key + emergency-contact waiting period)
6. ⬜ Breach monitoring via k-anonymity range queries

## A note on scope & threat model

The hardest part of a password manager isn't features — it's making sure the
server can never expose secrets even if fully compromised. That's why the crypto
core came first and is the only part with tests. Treat the stubbed pieces as
the *contract*; the crypto package is the *guarantee*.
