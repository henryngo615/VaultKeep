// Popup: unlock the vault, then push the decrypted credentials into the
// background worker's session so content scripts can request autofill.
// In a full build, unlock derives the key via @vaultkeep/crypto and decrypts
// the synced vault; here it wires the message flow.

const $ = (id) => document.getElementById(id);
const hasChrome = typeof chrome !== "undefined" && chrome.runtime;

function showUnlocked() {
  $("locked").classList.add("hidden");
  $("unlocked").classList.remove("hidden");
  $("chip").classList.add("on");
  $("chipText").textContent = "Unlocked";
}

// When opened outside the extension (e.g. a standalone preview), show the
// unlocked state so the autofill UI is visible without a real vault session.
if (!hasChrome) {
  showUnlocked();
}

$("unlock")?.addEventListener("click", async () => {
  const master = $("master").value;
  if (!master) return;
  if (!hasChrome) return showUnlocked();

  // TODO: derive key + decrypt vault (shared @vaultkeep/crypto + sync client).
  const credentials = []; // <- decrypted Credential[] goes here
  chrome.runtime.sendMessage({ kind: "session:set", credentials }, (resp) => {
    if (resp?.ok) showUnlocked();
    else $("status").textContent = "Failed to unlock";
  });
});
