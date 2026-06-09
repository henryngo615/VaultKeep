import { describe, it, expect } from "vitest";
import { isAutofillSafe } from "../src/phishing.js";
import { classifyField } from "../src/classify.js";
import { matchCredentials, type Credential } from "../src/matcher.js";
import { analyzeForm, planFill, type FormField } from "../src/autofill.js";

describe("phishing guard", () => {
  it("allows an exact-origin HTTPS match", () => {
    expect(isAutofillSafe("https://amazon.com/login", "https://amazon.com").safe).toBe(true);
  });
  it("blocks a look-alike domain", () => {
    const r = isAutofillSafe("https://amazon.com", "https://amaz0n.com");
    expect(r.safe).toBe(false);
  });
  it("blocks non-HTTPS pages", () => {
    expect(isAutofillSafe("https://amazon.com", "http://amazon.com").safe).toBe(false);
  });
});

describe("field classification", () => {
  it("uses the password type", () => {
    expect(classifyField({ type: "password" })).toBe("password");
  });
  it("honors autocomplete=username over generic text", () => {
    expect(classifyField({ type: "text", autocomplete: "username" })).toBe("username");
  });
  it("detects email inputs", () => {
    expect(classifyField({ type: "email" })).toBe("email");
  });
  it("detects OTP fields by name", () => {
    expect(classifyField({ type: "text", name: "otp_code" })).toBe("otp");
  });
  it("falls back to unknown for a bare text field", () => {
    expect(classifyField({ type: "text", name: "q" })).toBe("unknown");
  });
});

describe("credential matching (origin-scoped)", () => {
  const creds: Credential[] = [
    { id: "1", title: "Amazon", username: "me@x.com", password: "pw", url: "https://amazon.com" },
    { id: "2", title: "Bank", username: "me", password: "pw2", url: "https://bank.com" },
    { id: "3", title: "NoUrl", username: "u", password: "p" },
  ];

  it("offers only credentials for the current exact origin", () => {
    const m = matchCredentials(creds, "https://amazon.com");
    expect(m.map((x) => x.credential.id)).toEqual(["1"]);
  });

  it("offers nothing on a phishing look-alike", () => {
    expect(matchCredentials(creds, "https://amaz0n.com")).toHaveLength(0);
  });

  it("offers nothing over HTTP", () => {
    expect(matchCredentials(creds, "http://amazon.com")).toHaveLength(0);
  });
});

describe("form analysis", () => {
  it("labels the text field before a password as the username", () => {
    const fields: FormField[] = [
      { ref: "#u", input: { type: "text", name: "field1" } },
      { ref: "#p", input: { type: "password" } },
    ];
    const form = analyzeForm(fields);
    expect(form.hasPassword).toBe(true);
    expect(form.fields.find((f) => f.ref === "#u")!.kind).toBe("username");
  });

  it("leaves a search box alone when there is no password", () => {
    const form = analyzeForm([{ ref: "#q", input: { type: "text", name: "search" } }]);
    expect(form.hasPassword).toBe(false);
    expect(form.fields[0].kind).toBe("unknown");
  });
});

describe("fill planning (the choke point)", () => {
  const cred: Credential = {
    id: "1", title: "Amazon", username: "me@x.com", password: "s3cret",
    url: "https://amazon.com",
  };
  const form = analyzeForm([
    { ref: "#u", input: { type: "text", autocomplete: "username" } },
    { ref: "#p", input: { type: "password" } },
  ]);

  it("fills username + password on an exact-origin HTTPS page", () => {
    const plan = planFill(form, cred, "https://amazon.com");
    expect(plan.status).toBe("fill");
    if (plan.status === "fill") {
      expect(plan.writes).toContainEqual({ ref: "#u", value: "me@x.com" });
      expect(plan.writes).toContainEqual({ ref: "#p", value: "s3cret" });
    }
  });

  it("BLOCKS filling on a look-alike domain even if asked directly", () => {
    const plan = planFill(form, cred, "https://amaz0n.com");
    expect(plan.status).toBe("blocked");
  });

  it("BLOCKS filling a password over HTTP", () => {
    const plan = planFill(form, cred, "http://amazon.com");
    expect(plan.status).toBe("blocked");
  });

  it("never writes into an OTP field", () => {
    const otpForm = analyzeForm([
      { ref: "#p", input: { type: "password" } },
      { ref: "#otp", input: { type: "text", name: "one-time-code", autocomplete: "one-time-code" } },
    ]);
    const plan = planFill(otpForm, cred, "https://amazon.com");
    if (plan.status === "fill") {
      expect(plan.writes.find((w) => w.ref === "#otp")).toBeUndefined();
    }
  });
});
