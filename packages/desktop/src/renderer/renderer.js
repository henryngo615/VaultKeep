// Renderer: pure UI. All crypto/storage happens in the main process via the
// `window.vault` bridge exposed by preload.cjs. This script never sees the key.

const $ = (id) => document.getElementById(id);
// NB: avoid local names that collide with globals — `window.vault` is the
// preload bridge and `window.status` is built-in, so a top-level
// `const vault/status` throws "already declared".
const lockView = $("lock");
const vaultView = $("vault");
const statusEl = $("status");
const statusDot = $("statusDot");

function setStatus(text, online) {
  statusEl.textContent = text;
  statusDot.classList.toggle("on", !!online);
}

// Deterministic avatar color from a string.
const AVATAR_COLORS = [
  "#6366f1", "#8b5cf6", "#ec4899", "#f59e0b",
  "#10b981", "#06b6d4", "#ef4444", "#3b82f6",
];
function avatarFor(title) {
  let h = 0;
  for (const c of title) h = (h * 31 + c.charCodeAt(0)) >>> 0;
  const color = AVATAR_COLORS[h % AVATAR_COLORS.length];
  const initial = (title.trim()[0] || "?").toUpperCase();
  return { color, initial };
}

let allItems = [];

function renderList(filter = "") {
  const list = $("list");
  list.innerHTML = "";
  const q = filter.trim().toLowerCase();
  const items = q
    ? allItems.filter(
        (it) =>
          (it.title || "").toLowerCase().includes(q) ||
          (it.username || "").toLowerCase().includes(q) ||
          (it.url || "").toLowerCase().includes(q)
      )
    : allItems;

  if (!items.length) {
    list.innerHTML = q
      ? '<div class="empty"><div class="big">🔍</div>No matches.</div>'
      : '<div class="empty"><div class="big">🗝️</div>Your vault is empty.<br>Add your first login above.</div>';
    return;
  }

  for (const it of items) {
    const { color, initial } = avatarFor(it.title || "?");
    const el = document.createElement("div");
    el.className = "item";
    el.innerHTML = `
      <div class="item-head">
        <div class="avatar" style="background:${color}"></div>
        <div style="min-width:0">
          <div class="t"></div>
          <div class="u"></div>
        </div>
        <span class="chev">›</span>
      </div>
      <div class="detail hidden">
        <div class="field"><span class="lbl">User</span>
          <code class="uname"></code>
          <button class="copy" data-copy="uname">Copy</button></div>
        <div class="field"><span class="lbl">Password</span>
          <code class="pw">••••••••••</code>
          <button class="reveal">Show</button>
          <button class="copy" data-copy="pw">Copy</button></div>
      </div>`;
    el.querySelector(".avatar").textContent = initial;
    el.querySelector(".t").textContent = it.title;
    el.querySelector(".u").textContent = it.username || it.url || it.type;
    el.querySelector(".uname").textContent = it.username || "—";

    const detail = el.querySelector(".detail");
    const pwEl = el.querySelector(".pw");
    let shown = false;

    el.addEventListener("click", (e) => {
      if (e.target.closest("button")) return;
      detail.classList.toggle("hidden");
      el.classList.toggle("open");
    });

    el.querySelector(".reveal").addEventListener("click", (e) => {
      shown = !shown;
      pwEl.textContent = shown ? it.password || "—" : "••••••••••";
      e.target.textContent = shown ? "Hide" : "Show";
    });

    for (const btn of el.querySelectorAll(".copy")) {
      btn.addEventListener("click", async () => {
        const value = btn.dataset.copy === "pw" ? it.password : it.username;
        await navigator.clipboard.writeText(value || "");
        const old = btn.textContent;
        btn.textContent = "Copied!";
        setTimeout(() => (btn.textContent = old), 1200);
      });
    }
    list.appendChild(el);
  }
}

async function refresh() {
  allItems = await window.vault.list();
  renderList($("search")?.value || "");
}

function showVault() {
  lockView.classList.add("hidden");
  vaultView.classList.remove("hidden");
  setStatus("Unlocked", true);
  // Offer "disable biometrics" only while actually enrolled.
  window.vault.bioStatus().then((s) => {
    $("bioOffBtn").classList.toggle("hidden", !s.enrolled);
  });
  refresh();
}

// Surface biometric options if the OS supports them.
let bioAvailable = false;
(async () => {
  const s = await window.vault.bioStatus();
  bioAvailable = s.available;
  const label = s.platform === "darwin" ? "Touch ID" : s.platform === "win32" ? "Windows Hello" : "biometrics";
  $("bioBtn").textContent = `Unlock with ${label}`;
  $("enrollLabel").textContent = `Enable ${label} unlock`;
  $("bioOffBtn").title = `Disable ${label} unlock (wipes the wrapped key)`;
  if (s.enrolled) $("bioBtn").classList.remove("hidden");
  if (s.available) $("enrollRow").classList.remove("hidden");
})();

// --- Mode tabs: local unlock vs online sign-in ---
function setMode(online) {
  $("localPane").classList.toggle("hidden", online);
  $("onlinePane").classList.toggle("hidden", !online);
  $("tabOnline").classList.toggle("active", online);
  $("tabLocal").classList.toggle("active", !online);
  $("lockErr").textContent = "";
}
$("tabLocal").onclick = () => setMode(false);
$("tabOnline").onclick = () => setMode(true);

// Show the online tab's enrollment hint based on whether a device exists.
(async () => {
  const st = await window.vault.accountStatus();
  $("onlineHint").textContent = st.enrolled
    ? `Sign in to ${new URL(st.serverUrl).host}. The server never sees your password.`
    : `New here? Create an account on ${new URL(st.serverUrl).host} first.`;
  // This is a trusted device → offer passwordless device sign-in.
  if (st.enrolled) $("deviceLoginBtn").classList.remove("hidden");
})();

$("deviceLoginBtn").onclick = async () => {
  const email = $("email").value.trim();
  const pw = $("onlinePass").value;
  if (!email || !pw) return ($("lockErr").textContent = "Email and password required");
  $("lockErr").textContent = "Verifying this device…";
  const res = await window.vault.loginWithDevice(email, pw);
  if (res.ok) {
    $("onlinePass").value = "";
    showVault();
  } else {
    $("lockErr").textContent = res.error;
  }
};

$("unlockBtn").onclick = async () => {
  const pw = $("master").value;
  const res = await window.vault.unlock(pw);
  if (res.ok) {
    // Opt-in AFTER unlock: main wraps a copy of the derived key behind the OS
    // keystore. The password plays no part and never re-crosses IPC.
    if ($("enrollChk").checked) await window.vault.bioEnroll();
    $("master").value = "";
    showVault();
  } else {
    $("lockErr").textContent = res.error;
  }
};

$("registerBtn").onclick = async () => {
  const email = $("email").value.trim();
  const pw = $("onlinePass").value;
  if (!email || !pw) return ($("lockErr").textContent = "Email and password required");
  $("lockErr").textContent = "Creating account…";
  const res = await window.vault.register(email, pw);
  if (!res.ok) return ($("lockErr").textContent = res.error);
  // Show the TOTP QR enrollment step.
  $("qrImg").src = res.qr;
  $("totpSecret").textContent = res.secret;
  $("onlinePane").classList.add("hidden");
  $("enrollPane").classList.remove("hidden");
  $("lockErr").textContent = "";
};

$("confirmBtn").onclick = async () => {
  const code = $("enrollCode").value.trim();
  if (!/^\d{6}$/.test(code)) return ($("lockErr").textContent = "Enter the 6-digit code");
  const res = await window.vault.confirmMfa(code);
  if (res.ok) {
    $("enrollPane").classList.add("hidden");
    $("onlinePane").classList.remove("hidden");
    $("mfaCode").value = code;
    $("lockErr").textContent = "MFA enabled ✓ — now click Sign in.";
  } else {
    $("lockErr").textContent = res.error;
  }
};

$("loginBtn").onclick = async () => {
  const email = $("email").value.trim();
  const pw = $("onlinePass").value;
  const code = $("mfaCode").value.trim();
  if (!email || !pw) return ($("lockErr").textContent = "Email and password required");
  $("lockErr").textContent = "Signing in…";
  const res = await window.vault.login(email, pw, code || "000000");
  if (res.ok) {
    $("onlinePass").value = $("mfaCode").value = "";
    showVault();
  } else {
    $("lockErr").textContent = res.error;
  }
};

$("bioBtn").onclick = async () => {
  const res = await window.vault.bioUnlock();
  if (res.ok) showVault();
  else {
    $("lockErr").textContent = res.error;
    // A wiped/stale enrollment hides the button until re-enrolled.
    const s = await window.vault.bioStatus();
    $("bioBtn").classList.toggle("hidden", !s.enrolled);
  }
};

$("bioOffBtn").onclick = async () => {
  await window.vault.bioUnenroll();
  $("bioOffBtn").classList.add("hidden");
  $("bioBtn").classList.add("hidden");
  setStatus("Biometric unlock disabled", true);
};

$("lockBtn").onclick = async () => {
  await window.vault.lock();
  vaultView.classList.add("hidden");
  lockView.classList.remove("hidden");
  setStatus("Locked", false);
};

// Live search filter.
$("search").addEventListener("input", (e) => renderList(e.target.value));

$("addBtn").onclick = async () => {
  const title = $("newTitle").value.trim();
  if (!title) return;
  await window.vault.add({
    type: "login",
    title,
    username: $("newUser").value.trim(),
    password: $("newPass").value,
  });
  $("newTitle").value = $("newUser").value = $("newPass").value = "";
  $("genOut").classList.add("hidden");
  refresh();
};

$("genBtn").onclick = async () => {
  const pw = await window.vault.genPassword({
    length: 20, uppercase: true, lowercase: true, numbers: true, symbols: true,
  });
  $("newPass").value = pw;
  const out = $("genOut");
  out.textContent = pw;
  out.classList.remove("hidden");
};

$("healthBtn").onclick = async () => {
  const card = $("healthCard");
  if (!card.classList.contains("hidden")) return card.classList.add("hidden"); // toggle off
  $("healthSummary").textContent = "Checking…";
  $("healthList").innerHTML = "";
  card.classList.remove("hidden");

  const r = await window.vault.health();
  if (r.error) return ($("healthSummary").textContent = r.error);

  const s = r.summary;
  $("healthSummary").textContent =
    `${s.total} password${s.total === 1 ? "" : "s"} checked — ` +
    `${s.breached} breached, ${s.reused} reused, ${s.weak} weak` +
    (r.breachCheckAvailable ? "" : " (breach database unreachable — showing offline checks only)");

  const flagged = r.items.filter((i) => i.reasons.length > 0);
  if (!flagged.length) {
    $("healthList").innerHTML = '<p class="muted" style="margin:0">✅ No problems found.</p>';
    return;
  }
  for (const it of flagged) {
    const row = document.createElement("div");
    row.style.cssText = "padding:8px 0; border-top:1px solid var(--border)";
    const badges = [
      it.breached ? "🔴 breached" : "",
      it.reused ? "🟠 reused" : "",
      it.weak ? "🟡 weak" : "",
    ].filter(Boolean).join("  ");
    const title = document.createElement("div");
    title.innerHTML = `<b></b> <span class="muted" style="font-size:11px"></span>`;
    title.querySelector("b").textContent = it.title;
    title.querySelector("span").textContent = badges;
    const why = document.createElement("div");
    why.className = "muted";
    why.style.fontSize = "11px";
    why.textContent = it.reasons.join(" · ");
    row.append(title, why);
    $("healthList").appendChild(row);
  }
};

$("syncBtn").onclick = async () => {
  setStatus("Syncing…", true);
  try {
    const r = await window.vault.sync();
    setStatus(`Synced ↑${r.pushed} ↓${r.pulled}` + (r.conflicts ? ` ⚠${r.conflicts}` : ""), true);
    refresh();
  } catch (e) {
    setStatus("Offline", false);
  }
};
