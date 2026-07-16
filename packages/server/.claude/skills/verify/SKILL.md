---
name: verify
description: Build, launch, and drive the VaultKeep sync server to verify changes end-to-end
---

# Verifying @vaultkeep/server changes

## Build & launch

```bash
npm run build --workspace=@vaultkeep/crypto   # server imports crypto's dist/
cd packages/server && npx tsc

# File-backed mode (zero setup):
PORT=8791 VK_DB=/tmp/vk-db.json node dist/src/main.js

# Postgres mode: needs a live DB + migrations first
DATABASE_URL=postgresql://... npx prisma migrate deploy
DATABASE_URL=postgresql://... PORT=8791 node dist/src/main.js
```

No Docker on this machine — boot a real throwaway Postgres with the
`embedded-postgres` dev dependency (see `test/helpers/live-postgres.ts` for the
API: `initialise()` → `start()` → `createDatabase(...)`). Client must be
generated once: `npx prisma generate`.

## Driving the flow (HTTP surface)

Full zero-knowledge flow, in order: `POST /auth/register` (returns
`mfa.secret`) → `POST /auth/mfa/confirm` (TOTP code) → `POST /devices/enroll`
(first device auto-approved) → `POST /auth/login` (pre-MFA token) →
`POST /auth/mfa` (full token) → `PUT/GET /vault/items[/:id]` with Bearer token.

- Compute valid TOTP codes with `currentCode(secret)` from
  `dist/src/mfa/totp.service.js` (simulates the authenticator app).
- Generate device keys / approval signatures with `generateSigningKeys()` +
  `signMessage(priv, "approve-device:<id>")` from `packages/crypto/dist`.
- Node 24's global `fetch` works fine as the driver; no jq on this machine.

## Guard probes worth repeating

- Pre-MFA token on `/vault/items` → 403 "MFA required"
- Full token from an unapproved (second) device → 403 "device not approved"
- Stale `baseVersion` on PUT → 409 conflict with server copy
- Forged approval signature → 403 "invalid approval signature"
- Restart the server → data must survive in Postgres mode, and the JSON file
  must stay untouched
