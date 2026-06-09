/**
 * Content script (runs in the page). Its ONLY job is DOM I/O: read input
 * attributes into descriptors, hand them to the tested core, and write back the
 * plan's values. All security decisions live in the core modules, not here.
 *
 * The script never holds the vault key. It requests fill plans from the
 * background service worker (which talks to the unlocked vault) over messaging.
 */
import { analyzeForm, type FormField } from "./autofill.js";
import type { InputDescriptor } from "./classify.js";

function describe(el: HTMLInputElement): InputDescriptor {
  return {
    type: el.type,
    name: el.name || undefined,
    id: el.id || undefined,
    autocomplete: el.autocomplete || undefined,
    placeholder: el.placeholder || undefined,
    ariaLabel: el.getAttribute("aria-label") || undefined,
  };
}

/** Build a stable ref we can use to find the element again when filling. */
function refFor(el: HTMLInputElement, i: number): string {
  if (!el.dataset.vkRef) el.dataset.vkRef = `vk-${i}`;
  return `[data-vk-ref="${el.dataset.vkRef}"]`;
}

function collectForms(): { form: ReturnType<typeof analyzeForm>; origin: string } | null {
  const inputs = Array.from(document.querySelectorAll("input")).filter(
    (el) =>
      ["text", "email", "password", "tel"].includes(el.type) && el.offsetParent !== null
  ) as HTMLInputElement[];
  if (!inputs.some((el) => el.type === "password")) return null;

  const fields: FormField[] = inputs.map((el, i) => ({
    ref: refFor(el, i),
    input: describe(el),
  }));
  return { form: analyzeForm(fields), origin: location.origin };
}

/** Apply a fill plan from the background worker. */
function applyWrites(writes: Array<{ ref: string; value: string }>) {
  for (const w of writes) {
    const el = document.querySelector(w.ref) as HTMLInputElement | null;
    if (!el) continue;
    el.focus();
    el.value = w.value;
    // Fire the events frameworks (React/Vue) listen for.
    el.dispatchEvent(new Event("input", { bubbles: true }));
    el.dispatchEvent(new Event("change", { bubbles: true }));
  }
}

// Ask the background worker whether we have a credential for this page.
const detected = collectForms();
if (detected) {
  chrome.runtime.sendMessage(
    { kind: "autofill:request", origin: detected.origin, form: detected.form },
    (resp: { status: string; writes?: Array<{ ref: string; value: string }> }) => {
      if (resp?.status === "fill" && resp.writes) applyWrites(resp.writes);
    }
  );
}

// Offer to save newly-submitted credentials.
window.addEventListener(
  "submit",
  (e) => {
    const form = e.target as HTMLFormElement;
    const pw = form.querySelector('input[type="password"]') as HTMLInputElement | null;
    if (!pw?.value) return;
    const user = form.querySelector(
      'input[type="text"], input[type="email"]'
    ) as HTMLInputElement | null;
    chrome.runtime.sendMessage({
      kind: "save:offer",
      origin: location.origin,
      username: user?.value,
      password: pw.value,
    });
  },
  true
);
