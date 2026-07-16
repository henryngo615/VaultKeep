// VaultKeep web vault — client logic. All crypto runs in the browser via
// vaultcrypto.js; the server only ever sees ciphertext and the auth verifier.

const $ = (id) => document.getElementById(id);
const VC = window.VaultCrypto;
const API = ""; // same origin

// In-memory session (never persisted to disk; lost on reload by design).
let session = null;      // { token, userId, email }
let aesKey = null;       // CryptoKey for vault encryption
let items = [];          // decrypted VaultItem[]
let pendingUserId = null;

async function api(path, { method = "GET", body, token } = {}) {
  const res = await fetch(API + path, {
    method,
    headers: {
      "content-type": "application/json",
      ...(token ? { authorization: "Bearer " + token } : {}),
    },
    body: body ? JSON.stringify(body) : undefined,
  });
  let data = {};
  try { data = await res.json(); } catch {}
  return { status: res.status, ok: res.ok, data };
}

// Each browser persists its enrolled deviceId per email (localStorage is fine —
// it's just a non-secret device handle; the keys here are placeholders since the
// web client authenticates via TOTP, not device signatures).
function deviceKey(email) { return "vk_device_" + email.toLowerCase(); }
function loadDevice(email) {
  try { return JSON.parse(localStorage.getItem(deviceKey(email))); } catch { return null; }
}
function saveDevice(email, d) { localStorage.setItem(deviceKey(email), JSON.stringify(d)); }

function setErr(el, msg, ok = false) { el.textContent = msg; el.classList.toggle("ok", ok); }

// ---- Auth tabs ----
$("tabLogin").onclick = () => switchAuth("login");
$("tabReg").onclick = () => switchAuth("reg");
function switchAuth(which) {
  $("loginPane").classList.toggle("hidden", which !== "login");
  $("regPane").classList.toggle("hidden", which !== "reg");
  $("enrollPane").classList.add("hidden");
  $("tabLogin").classList.toggle("active", which === "login");
  $("tabReg").classList.toggle("active", which === "reg");
  setErr($("authErr"), "");
}

// ---- Register ----
$("regBtn").onclick = async () => {
  const email = $("rg_email").value.trim();
  const pw = $("rg_pw").value;
  if (!email || pw.length < 8) return setErr($("authErr"), "Use a real email and an 8+ char password.");
  setErr($("authErr"), "Creating account…");

  const saltB64 = VC.randomSaltB64();
  const { keyBits } = await VC.deriveKey(pw, saltB64, VC.DEFAULT_KDF);
  const authVerifier = await VC.deriveAuthVerifier(keyBits, pw);

  const reg = await api("/auth/register", {
    method: "POST",
    body: {
      email, authVerifier, kdfSalt: saltB64,
      kdfMemoryKiB: VC.DEFAULT_KDF.memoryKiB,
      kdfIterations: VC.DEFAULT_KDF.iterations,
      kdfParallel: VC.DEFAULT_KDF.parallelism,
    },
  });
  if (reg.status !== 201) return setErr($("authErr"), reg.data.error || "Registration failed");

  pendingUserId = reg.data.userId;
  // Enroll this browser as a device (placeholder keys; TOTP is the 2nd factor).
  const rand = () => btoa(String.fromCharCode(...crypto.getRandomValues(new Uint8Array(32))));
  const dev = await api("/devices/enroll", {
    method: "POST",
    body: { userId: pendingUserId, name: "Web browser", platform: "web", publicKey: rand(), signingPublicKey: rand() },
  });
  saveDevice(email, { deviceId: dev.data.device.id, email });

  // Show TOTP enrollment.
  $("qrImg").src = reg.data.mfa.qr;
  $("totpKey").textContent = reg.data.mfa.secret;
  $("regPane").classList.add("hidden");
  $("enrollPane").classList.remove("hidden");
  setErr($("authErr"), "");
};

$("enrollBtn").onclick = async () => {
  const code = $("en_code").value.trim();
  if (!/^\d{6}$/.test(code)) return setErr($("authErr"), "Enter the 6-digit code");
  const r = await api("/auth/mfa/confirm", { method: "POST", body: { userId: pendingUserId, code } });
  if (r.status !== 200) return setErr($("authErr"), "Code didn't match — try the current one.");
  setErr($("authErr"), "2FA enabled ✓ — signing you in…", true);
  // Auto-fill login with the same email so they just sign in.
  $("li_email").value = $("rg_email").value;
  switchAuth("login");
  setErr($("authErr"), "2FA enabled ✓ — enter your password and a code to sign in.", true);
};

// ---- Login ----
// Base64url helpers for WebAuthn's ArrayBuffer fields.
function b64url(buf) {
  return btoa(String.fromCharCode(...new Uint8Array(buf)))
    .replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
function fromB64url(s) {
  const bin = atob(s.replace(/-/g, "+").replace(/_/g, "/"));
  return Uint8Array.from(bin, (c) => c.charCodeAt(0));
}

/**
 * Shared first factor: derive key + verifier locally (the password never
 * leaves the browser) and exchange the verifier for a PRE-MFA token.
 * Returns null (with the error shown) on failure.
 */
async function passwordLogin() {
  const email = $("li_email").value.trim();
  const pw = $("li_pw").value;
  if (!email || !pw) return setErr($("authErr"), "Email and password required"), null;
  const device = loadDevice(email);
  if (!device) return setErr($("authErr"), "No device for this email in this browser. Create the account here first."), null;
  setErr($("authErr"), "Signing in…");

  // Fetch KDF params, derive key + verifier locally (same Argon2id as desktop).
  const kdf = await api("/auth/kdf", { method: "POST", body: { email } });
  const params = {
    memoryKiB: kdf.data.kdfMemoryKiB,
    iterations: kdf.data.kdfIterations,
    parallelism: kdf.data.kdfParallel,
  };
  const { aesKey: k, keyBits } = await VC.deriveKey(pw, kdf.data.kdfSalt, params);
  const authVerifier = await VC.deriveAuthVerifier(keyBits, pw);

  const login = await api("/auth/login", { method: "POST", body: { email, authVerifier, deviceId: device.deviceId } });
  if (login.status !== 200) return setErr($("authErr"), login.data.error || "Invalid credentials"), null;
  return { email, preToken: login.data.token, userId: login.data.userId, key: k };
}

function finishLogin(pre, fullToken) {
  session = { token: fullToken, userId: pre.userId, email: pre.email };
  aesKey = pre.key;
  return loadVault().then(showVault);
}

$("loginBtn").onclick = async () => {
  const code = $("li_code").value.trim();
  const pre = await passwordLogin();
  if (!pre) return;
  const mfa = await api("/auth/mfa", { method: "POST", body: { token: pre.preToken, code } });
  if (mfa.status !== 200) return setErr($("authErr"), mfa.data.error || "Invalid 2FA code");
  await finishLogin(pre, mfa.data.token);
};

// ---- Passkey as the second factor (browser-native WebAuthn) ----
$("passkeyBtn").onclick = async () => {
  const pre = await passwordLogin();
  if (!pre) return;
  const opt = await api("/auth/passkey/mfa/options", { method: "POST", body: { token: pre.preToken } });
  if (opt.status === 404) return setErr($("authErr"), "No passkey on this account yet — sign in with a code, then use “Add passkey”.");
  if (opt.status !== 200) return setErr($("authErr"), opt.data.error || "Passkey sign-in unavailable");
  const pub = opt.data.options;
  let cred;
  try {
    cred = await navigator.credentials.get({
      publicKey: {
        challenge: fromB64url(pub.challenge),
        rpId: pub.rpId,
        allowCredentials: pub.allowCredentials.map((c) => ({ type: "public-key", id: fromB64url(c.id) })),
        userVerification: pub.userVerification,
        timeout: pub.timeout,
      },
    });
  } catch {
    return setErr($("authErr"), "Passkey prompt was cancelled.");
  }
  const v = await api("/auth/passkey/mfa/verify", {
    method: "POST",
    body: {
      token: pre.preToken,
      credentialId: cred.id,
      clientDataJSON: b64url(cred.response.clientDataJSON),
      authenticatorData: b64url(cred.response.authenticatorData),
      signature: b64url(cred.response.signature),
    },
  });
  if (v.status !== 200) return setErr($("authErr"), v.data.error || "Passkey verification failed");
  await finishLogin(pre, v.data.token);
};

// ---- Register a passkey for the signed-in account ----
$("addPasskeyBtn").onclick = async () => {
  const btn = $("addPasskeyBtn");
  const opt = await api("/auth/passkey/register/options", { method: "POST", token: session.token });
  if (opt.status !== 200) return alert(opt.data.error || "Could not start passkey registration");
  const pub = opt.data.options;
  let cred;
  try {
    cred = await navigator.credentials.create({
      publicKey: {
        challenge: fromB64url(pub.challenge),
        rp: pub.rp,
        user: { id: fromB64url(pub.user.id), name: pub.user.name, displayName: pub.user.displayName },
        pubKeyCredParams: pub.pubKeyCredParams,
        excludeCredentials: pub.excludeCredentials.map((c) => ({ type: "public-key", id: fromB64url(c.id) })),
        authenticatorSelection: pub.authenticatorSelection,
        attestation: pub.attestation,
        timeout: pub.timeout,
      },
    });
  } catch {
    return; // user cancelled the platform prompt
  }
  const v = await api("/auth/passkey/register/verify", {
    method: "POST", token: session.token,
    body: {
      clientDataJSON: b64url(cred.response.clientDataJSON),
      attestationObject: b64url(cred.response.attestationObject),
    },
  });
  const old = btn.textContent;
  btn.textContent = v.status === 201 ? "✓ Passkey added" : "✗ " + (v.data.reason || "failed");
  setTimeout(() => (btn.textContent = old), 2500);
};

$("logoutBtn").onclick = () => {
  session = null; aesKey = null; items = [];
  $("li_pw").value = $("li_code").value = "";
  showAuth();
};

// ---- Vault ----
async function loadVault() {
  const r = await api("/vault/items", { token: session.token });
  items = [];
  for (const row of r.data.items || []) {
    try {
      const item = await VC.decryptJSON(aesKey, row.ciphertext);
      items.push({ ...item, _id: row.id, _version: row.version });
    } catch { /* skip undecryptable rows */ }
  }
  renderList($("search").value);
}

function avatar(title) {
  const colors = ["#6366f1","#8b5cf6","#ec4899","#f59e0b","#10b981","#06b6d4","#ef4444","#3b82f6"];
  let h = 0; for (const c of title) h = (h * 31 + c.charCodeAt(0)) >>> 0;
  return { color: colors[h % colors.length], initial: (title.trim()[0] || "?").toUpperCase() };
}

function renderList(filter = "") {
  const list = $("list");
  const q = filter.trim().toLowerCase();
  const shown = q ? items.filter((it) =>
    (it.title||"").toLowerCase().includes(q) || (it.username||"").toLowerCase().includes(q) || (it.url||"").toLowerCase().includes(q)
  ) : items;
  list.innerHTML = "";
  if (!shown.length) {
    list.innerHTML = q ? '<div class="empty"><div class="big">🔍</div>No matches.</div>'
      : '<div class="empty"><div class="big">🗝️</div>Your vault is empty.<br>Click “+ Add” to store your first login.</div>';
    return;
  }
  for (const it of shown) {
    const { color, initial } = avatar(it.title || "?");
    const el = document.createElement("div");
    el.className = "item";
    el.innerHTML = `
      <div class="item-head">
        <div class="av" style="background:${color}">${initial}</div>
        <div style="min-width:0"><div class="t"></div><div class="u"></div></div>
        <span class="chev">›</span>
      </div>
      <div class="detail hidden">
        <div class="field"><span class="lbl">User</span><code class="uname"></code><button class="ghost sm copy" data-f="username">Copy</button></div>
        <div class="field"><span class="lbl">Password</span><code class="pw">••••••••••</code><button class="ghost sm rev">Show</button><button class="ghost sm copy" data-f="password">Copy</button></div>
        <div class="field"><span class="lbl">Website</span><code class="url"></code></div>
        <div class="field"><span class="lbl"></span><button class="ghost sm del" style="color:#f87171">Delete</button></div>
      </div>`;
    el.querySelector(".t").textContent = it.title;
    el.querySelector(".u").textContent = it.username || it.url || "login";
    el.querySelector(".uname").textContent = it.username || "—";
    el.querySelector(".url").textContent = it.url || "—";
    const detail = el.querySelector(".detail"), pwEl = el.querySelector(".pw");
    let shown2 = false;
    el.querySelector(".item-head").onclick = () => { detail.classList.toggle("hidden"); el.classList.toggle("open"); };
    el.querySelector(".rev").onclick = (e) => { shown2 = !shown2; pwEl.textContent = shown2 ? (it.password||"—") : "••••••••••"; e.target.textContent = shown2 ? "Hide" : "Show"; };
    el.querySelectorAll(".copy").forEach((b) => b.onclick = async () => {
      await navigator.clipboard.writeText(it[b.dataset.f] || ""); const o = b.textContent; b.textContent = "Copied!"; setTimeout(() => b.textContent = o, 1000);
    });
    el.querySelector(".del").onclick = () => deleteItem(it);
    list.appendChild(el);
  }
}

async function saveItem(item) {
  const id = item._id || crypto.randomUUID();
  const ciphertext = await VC.encryptJSON(aesKey, {
    type: "login", title: item.title, username: item.username, password: item.password, url: item.url,
  });
  const r = await api(`/vault/items/${id}`, {
    method: "PUT", token: session.token,
    body: { ciphertext, baseVersion: item._version ?? null },
  });
  return r.status === 200;
}

async function deleteItem(it) {
  if (!confirm(`Delete “${it.title}”? This can't be undone.`)) return;
  await api(`/vault/items/${it._id}`, { method: "DELETE", token: session.token });
  await loadVault();
}

$("search").oninput = (e) => renderList(e.target.value);
$("syncBtn").onclick = loadVault;

// Add modal
$("addBtn").onclick = () => { $("modal").classList.remove("hidden"); ["m_title","m_url","m_user","m_pass"].forEach(i=>$(i).value=""); setErr($("m_err"),""); };
$("m_cancel").onclick = () => $("modal").classList.add("hidden");
$("m_gen").onclick = () => $("m_pass").value = VC.generatePassword(20);
$("m_save").onclick = async () => {
  const title = $("m_title").value.trim();
  if (!title) return setErr($("m_err"), "Title is required");
  const ok = await saveItem({ title, url: $("m_url").value.trim(), username: $("m_user").value.trim(), password: $("m_pass").value });
  if (!ok) return setErr($("m_err"), "Save failed");
  $("modal").classList.add("hidden");
  await loadVault();
};

// View switching
function showVault() {
  $("authView").classList.add("hidden");
  $("vaultView").classList.remove("hidden");
  $("whoami").classList.remove("hidden");
  $("who").textContent = session.email;
}
function showAuth() {
  $("vaultView").classList.add("hidden");
  $("whoami").classList.add("hidden");
  $("authView").classList.remove("hidden");
}

// Prefill email if a device exists in this browser.
(function init() {
  try {
    const lastEmail = Object.keys(localStorage).filter(k => k.startsWith("vk_device_"))
      .map(k => JSON.parse(localStorage.getItem(k)).email)[0];
    if (lastEmail) $("li_email").value = lastEmail;
  } catch {}
})();
