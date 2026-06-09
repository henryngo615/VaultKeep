# VaultKeep Browser Extension (MV3)

Autofill, save, and generate passwords. Chrome/Edge/Brave/Opera; Firefox via the
standard MV3 polyfill.

## Security-first autofill

All decisions live in DOM-free, unit-tested modules; the content script only
does DOM I/O. The fill planner is the choke point and **re-checks the phishing
guard itself** — it never trusts that the caller already matched.

```
content.ts (DOM)
   │  reads <input> attrs  →  InputDescriptor[]
   ▼
classify.ts  →  field kinds (username / password / email / otp / unknown)
   ▼
autofill.ts  analyzeForm()  →  AnalyzedForm
background.ts  matcher.ts  →  origin-scoped candidates (phishing.ts gate)
autofill.ts  planFill()    →  writes, OR "blocked: <reason>"
   ▼
content.ts (DOM)  applies writes, fires input/change events
```

## What's implemented + tested (`src/`)

| Module | Role |
|---|---|
| `phishing.ts` | exact-origin + HTTPS check (autofill safety) |
| `classify.ts` | field-kind heuristics (autocomplete attr authoritative) |
| `matcher.ts` | offers only credentials whose stored origin matches the page |
| `autofill.ts` | form analysis + the fill planner (the choke point) |
| `content.ts` | DOM adapter (MV3 content script) |
| `background.ts` | session cache + autofill request handler |

`test/extension.test.ts` (17 tests) proves the guarantees:
- offers **nothing** on a look-alike domain (`amaz0n.com`) or over HTTP
- the planner **blocks** filling even when asked directly on an unsafe origin
- the text field before a password is recognized as the username
- OTP fields are never auto-written

## Build & load

```bash
npm test            # core logic (no browser)
npm run build:ext   # emits dist/ (content, background, popup, classify, …)
# Chrome → chrome://extensions → Developer mode → Load unpacked → this folder
```

Content scripts are restricted to `https://*/*` in the manifest — defense in
depth against autofill on plaintext pages.

## Roadmap

- Wire the popup unlock to `@vaultkeep/crypto` + the sync client so
  `session:set` carries real decrypted credentials
- Inline credential picker when multiple matches exist
- Passkey (WebAuthn) create/get support
