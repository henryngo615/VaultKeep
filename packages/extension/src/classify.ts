/**
 * Field classification. The content script reads raw <input> attributes from the
 * page and hands us this DOM-free descriptor; we decide what each field is FOR.
 * Keeping this pure makes the (security-sensitive) heuristics unit-testable
 * without a browser.
 */
export interface InputDescriptor {
  type: string; // input "type" attribute
  name?: string;
  id?: string;
  autocomplete?: string;
  placeholder?: string;
  ariaLabel?: string;
}

export type FieldKind = "username" | "password" | "email" | "otp" | "unknown";

const USERNAME_HINTS = ["user", "login", "account", "userid", "uname"];
const EMAIL_HINTS = ["email", "e-mail"];
const OTP_HINTS = ["otp", "totp", "2fa", "mfa", "onetime", "one-time", "code"];

function haystack(d: InputDescriptor): string {
  return [d.name, d.id, d.autocomplete, d.placeholder, d.ariaLabel]
    .filter(Boolean)
    .join(" ")
    .toLowerCase();
}

export function classifyField(d: InputDescriptor): FieldKind {
  const type = d.type.toLowerCase();
  const ac = (d.autocomplete ?? "").toLowerCase();

  // The autocomplete attribute is authoritative when present (WHATWG spec).
  if (type === "password" || ac === "current-password" || ac === "new-password")
    return "password";
  if (ac === "username") return "username";
  if (ac === "email" || type === "email") return "email";
  if (ac === "one-time-code") return "otp";

  const h = haystack(d);
  if (OTP_HINTS.some((k) => h.includes(k))) return "otp";
  if (EMAIL_HINTS.some((k) => h.includes(k))) return "email";
  if (USERNAME_HINTS.some((k) => h.includes(k))) return "username";

  // A lone text input next to a password field is usually the username; that
  // contextual rule is applied by the form analyzer, not here.
  return "unknown";
}
