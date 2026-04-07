"use client";

import { useMemo, useState } from "react";
import { AUTH_ITERATIONS, AUTH_SALT_BYTES, authSaltToB64, deriveAuthVerifierB64 } from "@/lib/zkAuth";
import { randomBytes } from "@/lib/zkcrypto";
import { saveSession } from "@/lib/session";

type Status = { kind: "idle" } | { kind: "working" } | { kind: "ok"; userId: string } | { kind: "error"; message: string };

async function readApiError(res: Response): Promise<string> {
  const text = await res.text().catch(() => "");
  try {
    const json = JSON.parse(text) as { error?: string; detail?: string };
    return [json.error, json.detail].filter(Boolean).join(": ") || `http_${res.status}`;
  } catch {
    return text || `http_${res.status}`;
  }
}

export default function AuthPage() {
  const [mode, setMode] = useState<"register" | "unlock">("register");
  const [userId, setUserId] = useState("");
  const [masterPassword, setMasterPassword] = useState("");
  const [status, setStatus] = useState<Status>({ kind: "idle" });

  const canSubmit = useMemo(() => {
    if (!masterPassword) return false;
    if (mode === "unlock") return !!userId;
    return true;
  }, [masterPassword, mode, userId]);

  async function onRegister() {
    setStatus({ kind: "working" });
    try {
      const authSalt = randomBytes(AUTH_SALT_BYTES);
      const authSaltB64 = authSaltToB64(authSalt);
      const authVerifierB64 = await deriveAuthVerifierB64({
        masterPassword,
        authSalt,
        iterations: AUTH_ITERATIONS,
      });

      const res = await fetch("/api/auth/register", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          authSaltB64,
          authIterations: AUTH_ITERATIONS,
          authVerifierB64,
        }),
      });
      const data = (await res.json().catch(() => null)) as null | { userId?: string; error?: string };
      if (!res.ok || !data?.userId) throw new Error(await readApiError(res));
      setUserId(data.userId);
      setMode("unlock");
      saveSession({ userId: data.userId, authVerifierB64 });
      setStatus({ kind: "ok", userId: data.userId });
    } catch (e) {
      setStatus({ kind: "error", message: e instanceof Error ? e.message : "unknown_error" });
    }
  }

  async function onUnlock() {
    setStatus({ kind: "working" });
    try {
      const ch = await fetch("/api/auth/challenge", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ userId }),
      });
      const challenge = (await ch.json().catch(() => null)) as
        | null
        | { authSaltB64?: string; authIterations?: number; error?: string };
      if (!ch.ok || !challenge?.authSaltB64 || !challenge?.authIterations) {
        throw new Error(challenge?.error ?? "challenge_failed");
      }

      const authSalt = Uint8Array.from(atob(challenge.authSaltB64), (c) => c.charCodeAt(0));
      const authVerifierB64 = await deriveAuthVerifierB64({
        masterPassword,
        authSalt,
        iterations: challenge.authIterations,
      });

      const res = await fetch("/api/auth/login", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ userId, authVerifierB64 }),
      });
      const data = (await res.json().catch(() => null)) as null | { ok?: boolean; error?: string };
      if (!res.ok || !data?.ok) throw new Error(await readApiError(res));

      saveSession({ userId, authVerifierB64 });
      setStatus({ kind: "ok", userId });
    } catch (e) {
      setStatus({ kind: "error", message: e instanceof Error ? e.message : "unknown_error" });
    }
  }

  return (
    <div className="min-h-dvh bg-zinc-50 px-6 py-12 text-zinc-900 dark:bg-black dark:text-zinc-50">
      <div className="mx-auto w-full max-w-lg rounded-2xl border border-zinc-200 bg-white p-8 shadow-sm dark:border-zinc-800 dark:bg-zinc-950">
        <h1 className="text-2xl font-semibold tracking-tight">Vault access</h1>
        <p className="mt-2 text-sm text-zinc-600 dark:text-zinc-400">
          Prototype auth: server verifies a PBKDF2-derived verifier (not your password), and never sees your vault key.
        </p>

        <div className="mt-6 flex gap-2 rounded-xl bg-zinc-100 p-1 dark:bg-zinc-900">
          <button
            className={`h-10 flex-1 rounded-lg text-sm font-medium ${mode === "register" ? "bg-white shadow-sm dark:bg-zinc-950" : "text-zinc-600 dark:text-zinc-300"}`}
            onClick={() => setMode("register")}
            type="button"
          >
            Create
          </button>
          <button
            className={`h-10 flex-1 rounded-lg text-sm font-medium ${mode === "unlock" ? "bg-white shadow-sm dark:bg-zinc-950" : "text-zinc-600 dark:text-zinc-300"}`}
            onClick={() => setMode("unlock")}
            type="button"
          >
            Unlock
          </button>
        </div>

        {mode === "unlock" && (
          <label className="mt-6 block">
            <span className="text-sm font-medium">User ID</span>
            <input
              className="mt-2 w-full rounded-xl border border-zinc-200 bg-white px-3 py-2 text-sm outline-none focus:ring-2 focus:ring-zinc-300 dark:border-zinc-800 dark:bg-zinc-950 dark:focus:ring-zinc-700"
              value={userId}
              onChange={(e) => setUserId(e.target.value)}
              placeholder="Paste your user id"
              autoCapitalize="none"
              autoCorrect="off"
              spellCheck={false}
            />
          </label>
        )}

        <label className="mt-6 block">
          <span className="text-sm font-medium">Master password</span>
          <input
            className="mt-2 w-full rounded-xl border border-zinc-200 bg-white px-3 py-2 text-sm outline-none focus:ring-2 focus:ring-zinc-300 dark:border-zinc-800 dark:bg-zinc-950 dark:focus:ring-zinc-700"
            value={masterPassword}
            onChange={(e) => setMasterPassword(e.target.value)}
            type="password"
            placeholder="Never sent to server"
          />
        </label>

        <button
          className="mt-6 inline-flex h-11 w-full items-center justify-center rounded-xl bg-zinc-900 px-4 text-sm font-medium text-white hover:bg-zinc-800 disabled:cursor-not-allowed disabled:opacity-50 dark:bg-zinc-50 dark:text-zinc-900 dark:hover:bg-white"
          type="button"
          disabled={!canSubmit || status.kind === "working"}
          onClick={mode === "register" ? onRegister : onUnlock}
        >
          {status.kind === "working" ? "Working…" : mode === "register" ? "Create vault" : "Unlock"}
        </button>

        {status.kind === "ok" && (
          <div className="mt-6 rounded-xl border border-emerald-200 bg-emerald-50 p-4 text-sm text-emerald-900 dark:border-emerald-900/50 dark:bg-emerald-950/40 dark:text-emerald-200">
            <div className="font-medium">Unlocked</div>
            <div className="mt-1 break-all text-xs opacity-90">User ID: {status.userId}</div>
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

