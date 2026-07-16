// Popup: unlock the vault, then the background worker holds the session and
// serves autofill. The master password is sent ONLY to the background worker
// (same extension process), which feeds it to Argon2id and zeroes the key.

const $ = (id) => document.getElementById(id);
const hasChrome = typeof chrome !== "undefined" && chrome.runtime;

function showUnlocked(count) {
  $("locked").classList.add("hidden");
  $("unlocked").classList.remove("hidden");
  $("chip").classList.add("on");
  $("chipText").textContent = "Unlocked";
  if (count !== undefined) $("count").textContent = String(count);
}

function showLocked() {
  $("unlocked").classList.add("hidden");
  $("locked").classList.remove("hidden");
  $("chip").classList.remove("on");
  $("chipText").textContent = "Locked";
  $("master").value = $("code").value = "";
  $("status").textContent = "";
}

// Reflect the real session state when the popup opens.
if (hasChrome) {
  chrome.runtime.sendMessage({ kind: "session:status" }, (s) => {
    if (s?.unlocked) showUnlocked(s.count);
  });
  chrome.storage.local.get(["vk_server", "vk_email"]).then((bag) => {
    if (bag.vk_server) $("server").value = bag.vk_server;
    if (bag.vk_email) $("email").value = bag.vk_email;
  });
} else {
  // Standalone preview outside the extension: show the unlocked layout.
  showUnlocked(0);
}

$("unlock")?.addEventListener("click", () => {
  const email = $("email").value.trim();
  const password = $("master").value;
  const code = $("code").value.trim();
  if (!email || !password) return ($("status").textContent = "Email and master password required");
  if (!hasChrome) return showUnlocked(0);
  $("status").textContent = "Deriving key…";

  chrome.storage.local.set({ vk_email: email });
  chrome.runtime.sendMessage(
    { kind: "session:unlock", email, password, code, serverUrl: $("server").value.trim() },
    (resp) => {
      if (resp?.ok) {
        showUnlocked(resp.count);
        $("ustatus").textContent = resp.skipped ? `${resp.skipped} item(s) could not be decrypted.` : "";
      } else {
        $("status").textContent = resp?.reason || "Failed to unlock";
      }
    }
  );
});

$("lock")?.addEventListener("click", () => {
  if (!hasChrome) return showLocked();
  chrome.runtime.sendMessage({ kind: "session:lock" }, () => showLocked());
});
