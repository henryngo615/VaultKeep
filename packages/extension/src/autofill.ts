import { classifyField, type InputDescriptor, type FieldKind } from "./classify.js";
import { isAutofillSafe } from "./phishing.js";
import type { Credential } from "./matcher.js";

/** A field on the page, identified by an opaque ref the content script owns. */
export interface FormField {
  ref: string; // e.g. a CSS selector or generated id
  input: InputDescriptor;
}

export interface AnalyzedForm {
  fields: Array<{ ref: string; kind: FieldKind }>;
  hasPassword: boolean;
}

/**
 * Analyze a form's inputs into typed fields. Applies the contextual rule that a
 * lone `unknown` text field immediately before the password is the username.
 */
export function analyzeForm(fields: FormField[]): AnalyzedForm {
  const typed = fields.map((f) => ({ ref: f.ref, kind: classifyField(f.input) }));
  const pwIdx = typed.findIndex((t) => t.kind === "password");

  if (pwIdx > 0) {
    // Walk backwards from the password to find the nearest fillable text field.
    for (let i = pwIdx - 1; i >= 0; i--) {
      if (typed[i].kind === "unknown") {
        typed[i] = { ...typed[i], kind: "username" };
        break;
      }
      if (typed[i].kind === "username" || typed[i].kind === "email") break;
    }
  }
  return { fields: typed, hasPassword: pwIdx >= 0 };
}

export type FillPlan =
  | { status: "blocked"; reason: string }
  | { status: "fill"; writes: Array<{ ref: string; value: string }> };

/**
 * Decide exactly what to write into the page. This is the choke point: it
 * re-checks the phishing guard itself (defense in depth — never trusts that the
 * caller already matched) and refuses to put a password anywhere on a
 * non-HTTPS or mismatched-origin page.
 */
export function planFill(
  form: AnalyzedForm,
  credential: Credential,
  pageOrigin: string
): FillPlan {
  if (!credential.url) {
    return { status: "blocked", reason: "credential has no associated URL" };
  }
  const safe = isAutofillSafe(credential.url, pageOrigin);
  if (!safe.safe) {
    return { status: "blocked", reason: safe.reason ?? "unsafe origin" };
  }

  const writes: Array<{ ref: string; value: string }> = [];
  for (const f of form.fields) {
    if ((f.kind === "username" || f.kind === "email") && credential.username) {
      writes.push({ ref: f.ref, value: credential.username });
    } else if (f.kind === "password" && credential.password) {
      writes.push({ ref: f.ref, value: credential.password });
    }
    // OTP and unknown fields are never auto-written.
  }

  if (writes.length === 0) {
    return { status: "blocked", reason: "no matching fields to fill" };
  }
  return { status: "fill", writes };
}
