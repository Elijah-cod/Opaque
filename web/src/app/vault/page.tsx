"use client";

import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import Link from "next/link";
import { clearSession, loadSession } from "@/lib/session";
import { decryptJson, deriveAesGcmKey, importPasswordKey, PBKDF2_ITERATIONS, SALT_BYTES } from "@/lib/zkcrypto";
import { randomBytes } from "@/lib/zkcrypto";
import { encryptJson } from "@/lib/zkcrypto";

type VaultItemCipher = {
  id: string;
  updated_at: number;
  enc_salt_b64: string;
  enc_iterations: number;
  iv_b64: string;
  ciphertext_b64: string;
  metadata: string | null;
};

type VaultItemPlain = {
  title: string;
  username?: string;
  password?: string;
  url?: string;
  notes?: string;
};

const AUTO_LOCK_MS = 5 * 60 * 1000;

function b64ToBytes(b64: string): Uint8Array {
  return Uint8Array.from(atob(b64), (c) => c.charCodeAt(0));
}

export default function VaultPage() {
  const [masterPassword, setMasterPassword] = useState("");
  const [status, setStatus] = useState<"locked" | "unlocking" | "unlocked">("locked");
  const [error, setError] = useState<string | null>(null);
  const [items, setItems] = useState<Array<{ id: string; updatedAt: number; plain: VaultItemPlain }>>([]);
  const aesKeyRef = useRef<CryptoKey | null>(null);
  const session = useMemo(() => loadSession(), []);

  const lockTimer = useRef<number | null>(null);

  function lock() {
    aesKeyRef.current = null;
    setMasterPassword("");
    setItems([]);
    setStatus("locked");
  }

  const resetAutoLock = useCallback(() => {
    if (lockTimer.current) window.clearTimeout(lockTimer.current);
    lockTimer.current = window.setTimeout(() => {
      lock();
    }, AUTO_LOCK_MS);
  }, []);

  useEffect(() => {
    const onActivity = () => {
      if (status === "unlocked") resetAutoLock();
    };
    window.addEventListener("mousemove", onActivity);
    window.addEventListener("keydown", onActivity);
    window.addEventListener("mousedown", onActivity);
    window.addEventListener("touchstart", onActivity);
    return () => {
      window.removeEventListener("mousemove", onActivity);
      window.removeEventListener("keydown", onActivity);
      window.removeEventListener("mousedown", onActivity);
      window.removeEventListener("touchstart", onActivity);
      if (lockTimer.current) window.clearTimeout(lockTimer.current);
    };
  }, [resetAutoLock, status]);

  async function authFetch(input: string, init?: RequestInit) {
    if (!session) throw new Error("missing_session");
    const headers = new Headers(init?.headers ?? {});
    headers.set("x-user-id", session.userId);
    headers.set("x-auth-verifier", session.authVerifierB64);
    return fetch(input, { ...init, headers });
  }

  async function unlockAndLoad() {
    setError(null);
    if (!session) {
      setError("No session found. Go to /auth first.");
      return;
    }
    if (!masterPassword) {
      setError("Enter your master password.");
      return;
    }

    setStatus("unlocking");
    try {
      const passwordKey = await importPasswordKey(masterPassword);

      const res = await authFetch("/api/vault/list");
      const data = (await res.json()) as { items: VaultItemCipher[] } | { error: string };
      if (!res.ok || "error" in data) throw new Error("vault_list_failed");

      // For simplicity, derive a key per item salt/iterations.
      const plains: Array<{ id: string; updatedAt: number; plain: VaultItemPlain }> = [];
      for (const it of data.items) {
        const aesKey = await deriveAesGcmKey({
          passwordKey,
          salt: b64ToBytes(it.enc_salt_b64),
          iterations: it.enc_iterations,
        });
        const plain = await decryptJson<VaultItemPlain>({
          key: aesKey,
          ivB64: it.iv_b64,
          ciphertextB64: it.ciphertext_b64,
        });
        plains.push({ id: it.id, updatedAt: it.updated_at, plain });
      }

      // Cache the last-derived key only as a convenience for creates;
      // real design should use a single per-user vault salt stored server-side.
      aesKeyRef.current = await deriveAesGcmKey({
        passwordKey,
        salt: randomBytes(SALT_BYTES),
        iterations: PBKDF2_ITERATIONS,
      });

      setItems(plains);
      setStatus("unlocked");
      resetAutoLock();
    } catch (e) {
      setStatus("locked");
      setError(e instanceof Error ? e.message : "unlock_failed");
    }
  }

  async function createDemoItem() {
    setError(null);
    if (status !== "unlocked") return;
    if (!session) return;
    if (!masterPassword) {
      setError("Master password cleared or locked.");
      return;
    }
    try {
      const passwordKey = await importPasswordKey(masterPassword);
      const encSalt = randomBytes(SALT_BYTES);
      const aesKey = await deriveAesGcmKey({ passwordKey, salt: encSalt, iterations: PBKDF2_ITERATIONS });

      const payload: VaultItemPlain = {
        title: `Demo ${new Date().toLocaleTimeString()}`,
        username: "alice@example.com",
        password: "correct horse battery staple",
        url: "https://example.com",
      };
      const { ciphertextB64, ivB64 } = await encryptJson({ key: aesKey, payload });

      const res = await authFetch("/api/vault/item", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          encSaltB64: btoa(String.fromCharCode(...encSalt)),
          encIterations: PBKDF2_ITERATIONS,
          ivB64,
          ciphertextB64,
          metadata: null,
        }),
      });
      const data = (await res.json().catch(() => null)) as null | { id?: string; error?: string };
      if (!res.ok || !data?.id) throw new Error(data?.error ?? "create_failed");

      setItems((prev) => [{ id: data.id!, updatedAt: Date.now(), plain: payload }, ...prev]);
      resetAutoLock();
    } catch (e) {
      setError(e instanceof Error ? e.message : "create_failed");
    }
  }

  return (
    <div className="min-h-dvh bg-zinc-50 px-6 py-12 text-zinc-900 dark:bg-black dark:text-zinc-50">
      <div className="mx-auto w-full max-w-2xl rounded-2xl border border-zinc-200 bg-white p-8 shadow-sm dark:border-zinc-800 dark:bg-zinc-950">
        <div className="flex items-center justify-between gap-4">
          <div>
            <h1 className="text-2xl font-semibold tracking-tight">Vault</h1>
            <p className="mt-1 text-sm text-zinc-600 dark:text-zinc-400">
              Decryption happens locally. Auto-lock after 5 minutes of inactivity.
            </p>
          </div>
          <div className="flex items-center gap-2">
            <Link className="text-sm font-medium text-zinc-700 hover:underline dark:text-zinc-300" href="/auth">
              Auth
            </Link>
            <button
              type="button"
              className="inline-flex h-9 items-center justify-center rounded-xl border border-zinc-200 px-3 text-sm font-medium hover:bg-zinc-50 dark:border-zinc-800 dark:hover:bg-zinc-900"
              onClick={() => {
                clearSession();
                lock();
              }}
            >
              Sign out
            </button>
          </div>
        </div>

        {!session && (
          <div className="mt-6 rounded-xl border border-red-200 bg-red-50 p-4 text-sm text-red-900 dark:border-red-900/50 dark:bg-red-950/40 dark:text-red-200">
            Missing session. Go to <Link className="underline" href="/auth">/auth</Link>.
          </div>
        )}

        {status !== "unlocked" && (
          <div className="mt-6 grid gap-3">
            <label className="block">
              <span className="text-sm font-medium">Master password</span>
              <input
                className="mt-2 w-full rounded-xl border border-zinc-200 bg-white px-3 py-2 text-sm outline-none focus:ring-2 focus:ring-zinc-300 dark:border-zinc-800 dark:bg-zinc-950 dark:focus:ring-zinc-700"
                value={masterPassword}
                onChange={(e) => setMasterPassword(e.target.value)}
                type="password"
                placeholder="Used only to derive the vault key locally"
              />
            </label>
            <button
              className="inline-flex h-11 items-center justify-center rounded-xl bg-zinc-900 px-4 text-sm font-medium text-white hover:bg-zinc-800 disabled:cursor-not-allowed disabled:opacity-50 dark:bg-zinc-50 dark:text-zinc-900 dark:hover:bg-white"
              type="button"
              disabled={!session || !masterPassword || status === "unlocking"}
              onClick={unlockAndLoad}
            >
              {status === "unlocking" ? "Unlocking…" : "Unlock vault"}
            </button>
          </div>
        )}

        {status === "unlocked" && (
          <div className="mt-6 flex items-center gap-2">
            <button
              type="button"
              className="inline-flex h-10 items-center justify-center rounded-xl bg-zinc-900 px-4 text-sm font-medium text-white hover:bg-zinc-800 dark:bg-zinc-50 dark:text-zinc-900 dark:hover:bg-white"
              onClick={createDemoItem}
            >
              Add demo item (encrypted)
            </button>
            <button
              type="button"
              className="inline-flex h-10 items-center justify-center rounded-xl border border-zinc-200 px-4 text-sm font-medium hover:bg-zinc-50 dark:border-zinc-800 dark:hover:bg-zinc-900"
              onClick={() => {
                lock();
              }}
            >
              Lock
            </button>
          </div>
        )}

        {error && (
          <div className="mt-6 rounded-xl border border-red-200 bg-red-50 p-4 text-sm text-red-900 dark:border-red-900/50 dark:bg-red-950/40 dark:text-red-200">
            {error}
          </div>
        )}

        <div className="mt-8">
          <h2 className="text-sm font-semibold uppercase tracking-wide text-zinc-500 dark:text-zinc-400">
            Items
          </h2>
          <div className="mt-3 grid gap-3">
            {items.length === 0 ? (
              <div className="rounded-xl border border-zinc-200 p-4 text-sm text-zinc-600 dark:border-zinc-800 dark:text-zinc-400">
                No items yet.
              </div>
            ) : (
              items.map((it) => (
                <div key={it.id} className="rounded-xl border border-zinc-200 p-4 dark:border-zinc-800">
                  <div className="flex items-center justify-between gap-3">
                    <div className="font-medium">{it.plain.title}</div>
                    <div className="text-xs text-zinc-500 dark:text-zinc-400">
                      {new Date(it.updatedAt).toLocaleString()}
                    </div>
                  </div>
                  <div className="mt-2 grid gap-1 text-sm text-zinc-700 dark:text-zinc-300">
                    {it.plain.username && <div>Username: {it.plain.username}</div>}
                    {it.plain.password && <div>Password: {it.plain.password}</div>}
                    {it.plain.url && <div>URL: {it.plain.url}</div>}
                  </div>
                  <div className="mt-2 break-all text-[11px] text-zinc-500 dark:text-zinc-400">
                    ID: {it.id}
                  </div>
                </div>
              ))
            )}
          </div>
        </div>
      </div>
    </div>
  );
}

