"use client";

import Link from "next/link";
import { useMemo, useState } from "react";
import { bytesToBase64Url } from "@/lib/base64url";

type Step = "email" | "code" | "done";
type Status = { kind: "idle" } | { kind: "working" } | { kind: "error"; message: string };

function parseApiError(status: number, rawBody: string): string {
  const text = rawBody || "";
  try {
    const json = JSON.parse(text) as { error?: string; detail?: string };
    return [json.error, json.detail].filter(Boolean).join(": ") || `http_${status}`;
  } catch {
    return text || `http_${status}`;
  }
}

async function readJsonOnce<T>(res: Response): Promise<{ ok: boolean; status: number; bodyText: string; json: T | null }> {
  const bodyText = await res.text().catch(() => "");
  let json: T | null = null;
  try {
    json = JSON.parse(bodyText) as T;
  } catch {
    json = null;
  }
  return { ok: res.ok, status: res.status, bodyText, json };
}

export default function AuthPage() {
  const [step, setStep] = useState<Step>("email");
  const [email, setEmail] = useState("");
  const [code, setCode] = useState("");
  const [status, setStatus] = useState<Status>({ kind: "idle" });
  const [recoveryCode, setRecoveryCode] = useState<string | null>(null);

  const canSubmit = useMemo(() => {
    if (step === "email") return !!email;
    if (step === "code") return !!email && /^\d{6}$/.test(code);
    return false;
  }, [code, email, step]);

  async function onRequestOtp() {
    setStatus({ kind: "working" });
    try {
      const res = await fetch("/api/auth/request-otp", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ email }),
      });
      const parsed = await readJsonOnce<{ ok?: boolean; error?: string; detail?: string }>(res);
      if (!parsed.ok) throw new Error(parseApiError(parsed.status, parsed.bodyText));
      setStatus({ kind: "idle" });
      setStep("code");
    } catch (e) {
      setStatus({ kind: "error", message: e instanceof Error ? e.message : "unknown_error" });
    }
  }

  async function onVerifyOtp() {
    setStatus({ kind: "working" });
    try {
      const res = await fetch("/api/auth/verify-otp", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ email, code }),
      });
      const parsed = await readJsonOnce<{ ok?: boolean; error?: string; detail?: string }>(res);
      if (!parsed.ok || !parsed.json?.ok) throw new Error(parseApiError(parsed.status, parsed.bodyText));

      // Generate a “recovery kit” code for the user to store safely.
      // This is a UX flow; full cryptographic recovery will be wired to wrapped keys in a later hardening pass.
      const bytes = crypto.getRandomValues(new Uint8Array(32));
      const rc = bytesToBase64Url(bytes);
      setRecoveryCode(rc);
      setStatus({ kind: "idle" });
      setStep("done");
    } catch (e) {
      setStatus({ kind: "error", message: e instanceof Error ? e.message : "unknown_error" });
    }
  }

  function downloadRecoveryKit() {
    if (!recoveryCode) return;
    const contents = [
      "Opaque Vault — Recovery Kit",
      "",
      "Recovery code (save this somewhere safe):",
      recoveryCode,
      "",
      "What this is:",
      "- This code is a backup credential you should store offline (password manager, print, etc.).",
      "- If you lose your master password, your vault may be unrecoverable.",
      "",
      "Do NOT share this code.",
      "",
    ].join("\n");
    const blob = new Blob([contents], { type: "text/plain;charset=utf-8" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = "opaque-recovery-kit.txt";
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);
  }

  return (
    <div className="min-h-dvh bg-zinc-50 px-6 py-12 text-zinc-900 dark:bg-black dark:text-zinc-50">
      <div className="mx-auto w-full max-w-lg rounded-2xl border border-zinc-200 bg-white p-8 shadow-sm dark:border-zinc-800 dark:bg-zinc-950">
        <h1 className="text-2xl font-semibold tracking-tight">Sign in</h1>
        <p className="mt-2 text-sm text-zinc-600 dark:text-zinc-400">
          We’ll email you a one-time code. Your master password is only used on your device to unlock your vault.
        </p>

        <label className="mt-6 block">
          <span className="text-sm font-medium">Email address</span>
          <input
            className="mt-2 w-full rounded-xl border border-zinc-200 bg-white px-3 py-2 text-sm outline-none focus:ring-2 focus:ring-zinc-300 dark:border-zinc-800 dark:bg-zinc-950 dark:focus:ring-zinc-700"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            type="email"
            placeholder="you@example.com"
            autoCapitalize="none"
            autoCorrect="off"
            spellCheck={false}
          />
        </label>

        {step === "code" && (
          <label className="mt-4 block">
            <span className="text-sm font-medium">6-digit code</span>
            <input
              className="mt-2 w-full rounded-xl border border-zinc-200 bg-white px-3 py-2 text-sm outline-none focus:ring-2 focus:ring-zinc-300 dark:border-zinc-800 dark:bg-zinc-950 dark:focus:ring-zinc-700"
              value={code}
              onChange={(e) => setCode(e.target.value)}
              inputMode="numeric"
              placeholder="123456"
              autoComplete="one-time-code"
            />
          </label>
        )}

        <button
          className="mt-6 inline-flex h-11 w-full items-center justify-center rounded-xl bg-zinc-900 px-4 text-sm font-medium text-white hover:bg-zinc-800 disabled:cursor-not-allowed disabled:opacity-50 dark:bg-zinc-50 dark:text-zinc-900 dark:hover:bg-white"
          type="button"
          disabled={!canSubmit || status.kind === "working"}
          onClick={step === "email" ? onRequestOtp : onVerifyOtp}
        >
          {status.kind === "working"
            ? "Working…"
            : step === "email"
              ? "Send code"
              : step === "code"
                ? "Verify code"
                : "Continue"}
        </button>

        {step === "done" && (
          <div className="mt-6 rounded-xl border border-emerald-200 bg-emerald-50 p-4 text-sm text-emerald-900 dark:border-emerald-900/50 dark:bg-emerald-950/40 dark:text-emerald-200">
            <div className="font-medium">You’re signed in</div>
            <div className="mt-2 text-xs opacity-90">
              Next, unlock your vault on the Vault page using your master password.
            </div>
            {recoveryCode && (
              <div className="mt-4 rounded-lg border border-emerald-200 bg-white/60 p-3 text-xs dark:border-emerald-900/50 dark:bg-emerald-950/20">
                <div className="font-semibold">Recovery kit (save this)</div>
                <div className="mt-2 break-all font-mono">{recoveryCode}</div>
                <div className="mt-2 opacity-90">
                  Store this somewhere safe. If you lose your master password, recovery may not be possible.
                </div>
                <button
                  type="button"
                  className="mt-3 inline-flex h-9 items-center justify-center rounded-lg bg-emerald-700 px-3 text-xs font-medium text-white hover:bg-emerald-600 dark:bg-emerald-500 dark:text-emerald-950 dark:hover:bg-emerald-400"
                  onClick={downloadRecoveryKit}
                >
                  Download recovery kit
                </button>
              </div>
            )}
            <div className="mt-4">
              <Link className="font-medium underline" href="/vault">
                Go to Vault
              </Link>
            </div>
          </div>
        )}
        {status.kind === "error" && (
          <div className="mt-6 rounded-xl border border-red-200 bg-red-50 p-4 text-sm text-red-900 dark:border-red-900/50 dark:bg-red-950/40 dark:text-red-200">
            {status.message}
          </div>
        )}
      </div>
    </div>
  );
}

