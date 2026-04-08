"use client";

import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import Link from "next/link";
import { clearSession, loadSession } from "@/lib/session";
import { decryptJson, deriveAesGcmKey, importPasswordKey, PBKDF2_ITERATIONS } from "@/lib/zkcrypto";
import { encryptJson } from "@/lib/zkcrypto";

type VaultItemCipher = {
  id: string;
  updated_at: number;
  enc_salt_b64: string;
  enc_iterations: number;
  iv_b64: string;
  ciphertext_b64: string;
  metadata: string | null;
  title?: string | null;
  url_host?: string | null;
  tags?: string | null;
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

function generatePassword(len = 16): string {
  const alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789!@#$%^&*-_+=";
  const bytes = crypto.getRandomValues(new Uint8Array(len));
  let out = "";
  for (let i = 0; i < len; i++) out += alphabet[bytes[i] % alphabet.length];
  return out;
}

function urlHostOrNull(url: string | undefined): string | null {
  if (!url) return null;
  try {
    const u = new URL(url.startsWith("http") ? url : `https://${url}`);
    return u.host;
  } catch {
    return null;
  }
}

export default function VaultPage() {
  const [masterPassword, setMasterPassword] = useState("");
  const [status, setStatus] = useState<"locked" | "unlocking" | "unlocked">("locked");
  const [error, setError] = useState<string | null>(null);
  const [items, setItems] = useState<Array<{ id: string; updatedAt: number; plain: VaultItemPlain }>>([]);
  const [query, setQuery] = useState("");
  const [toast, setToast] = useState<string | null>(null);
  const [isEditing, setIsEditing] = useState(false);
  const [editingId, setEditingId] = useState<string | null>(null);
  const [formTitle, setFormTitle] = useState("");
  const [formUsername, setFormUsername] = useState("");
  const [formPassword, setFormPassword] = useState("");
  const [formUrl, setFormUrl] = useState("");
  const [formNotes, setFormNotes] = useState("");
  const aesKeyRef = useRef<CryptoKey | null>(null);
  const vaultSaltB64Ref = useRef<string | null>(null);
  const vaultIterationsRef = useRef<number | null>(null);
  const session = useMemo(() => loadSession(), []);

  const lockTimer = useRef<number | null>(null);

  function lock() {
    aesKeyRef.current = null;
    setMasterPassword("");
    setItems([]);
    setStatus("locked");
  }

  const pushToast = useCallback((msg: string) => {
    setToast(msg);
    window.setTimeout(() => setToast(null), 2500);
  }, []);

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
    const onBlurOrHide = () => {
      lock();
    };
    window.addEventListener("mousemove", onActivity);
    window.addEventListener("keydown", onActivity);
    window.addEventListener("mousedown", onActivity);
    window.addEventListener("touchstart", onActivity);
    window.addEventListener("blur", onBlurOrHide);
    document.addEventListener("visibilitychange", onBlurOrHide);
    return () => {
      window.removeEventListener("mousemove", onActivity);
      window.removeEventListener("keydown", onActivity);
      window.removeEventListener("mousedown", onActivity);
      window.removeEventListener("touchstart", onActivity);
      window.removeEventListener("blur", onBlurOrHide);
      document.removeEventListener("visibilitychange", onBlurOrHide);
      if (lockTimer.current) window.clearTimeout(lockTimer.current);
    };
  }, [resetAutoLock, status]);

  async function authFetch(input: string, init?: RequestInit) {
    // Production path: rely on httpOnly session cookie.
    // Temporary fallback: if legacy session exists, attach headers (requires OPAQUE_ENABLE_LEGACY_AUTH=1 server-side).
    const headers = new Headers(init?.headers ?? {});
    if (session?.userId && session?.authVerifierB64) {
      headers.set("x-user-id", session.userId);
      headers.set("x-auth-verifier", session.authVerifierB64);
    }
    return fetch(input, { ...init, headers, credentials: "include" });
  }

  async function loadItems(passwordKey: CryptoKey, q: string) {
    const vaultSaltB64 = vaultSaltB64Ref.current;
    const vaultIterations = vaultIterationsRef.current ?? PBKDF2_ITERATIONS;
    if (!vaultSaltB64) throw new Error("vault_locked");
    const vaultSalt = b64ToBytes(vaultSaltB64);

    const res = await authFetch(`/api/vault/list?q=${encodeURIComponent(q)}`);
    const data = (await res.json()) as { items: VaultItemCipher[] } | { error: string };
    if (!res.ok) throw new Error("vault_list_failed");
    if ("error" in data) throw new Error(data.error || "vault_list_failed");

    const plains: Array<{ id: string; updatedAt: number; plain: VaultItemPlain }> = [];
    for (const it of data.items) {
      const aesKey = await deriveAesGcmKey({
        passwordKey,
        salt: vaultSalt,
        iterations: vaultIterations,
      });
      const plain = await decryptJson<VaultItemPlain>({
        key: aesKey,
        ivB64: it.iv_b64,
        ciphertextB64: it.ciphertext_b64,
      });
      plains.push({ id: it.id, updatedAt: it.updated_at, plain });
    }
    setItems(plains);
  }

  async function unlockAndLoad() {
    setError(null);
    // If using cookie sessions, the UI doesn't need localStorage session at all.
    if (!masterPassword) {
      setError("Enter your master password.");
      return;
    }

    setStatus("unlocking");
    try {
      const passwordKey = await importPasswordKey(masterPassword);

      const kdfRes = await authFetch("/api/vault/kdf");
      const kdf = (await kdfRes.json().catch(() => null)) as
        | null
        | { vaultSaltB64?: string; vaultIterations?: number; error?: string };
      if (!kdfRes.ok || !kdf?.vaultSaltB64 || !kdf?.vaultIterations) {
        throw new Error(kdf?.error ?? "vault_kdf_failed");
      }
      const vaultSalt = b64ToBytes(kdf.vaultSaltB64);
      const vaultIterations = kdf.vaultIterations;
      vaultSaltB64Ref.current = kdf.vaultSaltB64;
      vaultIterationsRef.current = vaultIterations;

      aesKeyRef.current = await deriveAesGcmKey({
        passwordKey,
        salt: vaultSalt,
        iterations: vaultIterations,
      });
      setStatus("unlocked");
      resetAutoLock();

      await loadItems(passwordKey, query);
    } catch (e) {
      setStatus("locked");
      setError(e instanceof Error ? e.message : "unlock_failed");
    }
  }

  async function createDemoItem() {
    setError(null);
    if (status !== "unlocked") return;
    if (!masterPassword) {
      setError("Master password cleared or locked.");
      return;
    }
    try {
      const passwordKey = await importPasswordKey(masterPassword);
      const vaultSaltB64 = vaultSaltB64Ref.current;
      const vaultIterations = vaultIterationsRef.current ?? PBKDF2_ITERATIONS;
      if (!vaultSaltB64) throw new Error("vault_locked");
      const saltBytes = b64ToBytes(vaultSaltB64);
      const aesKey = await deriveAesGcmKey({ passwordKey, salt: saltBytes, iterations: vaultIterations });

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
          encSaltB64: vaultSaltB64,
          encIterations: vaultIterations,
          ivB64,
          ciphertextB64,
          title: payload.title,
          urlHost: urlHostOrNull(payload.url),
        }),
      });
      const data = (await res.json().catch(() => null)) as null | { id?: string; error?: string };
      if (!res.ok || !data?.id) throw new Error(data?.error ?? "create_failed");

      setItems((prev) => [{ id: data.id!, updatedAt: Date.now(), plain: payload }, ...prev]);
      pushToast("Saved");
      resetAutoLock();
    } catch (e) {
      setError(e instanceof Error ? e.message : "create_failed");
    }
  }

  async function saveForm() {
    setError(null);
    if (status !== "unlocked") return;
    if (!masterPassword) return;
    try {
      const passwordKey = await importPasswordKey(masterPassword);
      const vaultSaltB64 = vaultSaltB64Ref.current;
      const vaultIterations = vaultIterationsRef.current ?? PBKDF2_ITERATIONS;
      if (!vaultSaltB64) throw new Error("vault_locked");
      const saltBytes = b64ToBytes(vaultSaltB64);
      const aesKey = await deriveAesGcmKey({ passwordKey, salt: saltBytes, iterations: vaultIterations });

      const payload: VaultItemPlain = {
        title: formTitle.trim() || "Untitled",
        username: formUsername.trim() || undefined,
        password: formPassword || undefined,
        url: formUrl.trim() || undefined,
        notes: formNotes.trim() || undefined,
      };
      const { ciphertextB64, ivB64 } = await encryptJson({ key: aesKey, payload });

      const body = {
        encSaltB64: vaultSaltB64,
        encIterations: vaultIterations,
        ivB64,
        ciphertextB64,
        title: payload.title,
        urlHost: urlHostOrNull(payload.url),
      };

      if (editingId) {
        const res = await authFetch("/api/vault/item", {
          method: "PUT",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({ id: editingId, ...body }),
        });
        if (!res.ok) throw new Error("save_failed");
      } else {
        const res = await authFetch("/api/vault/item", {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify(body),
        });
        const data = (await res.json().catch(() => null)) as null | { id?: string };
        if (!res.ok || !data?.id) throw new Error("save_failed");
      }

      await loadItems(passwordKey, query);
      setIsEditing(false);
      setEditingId(null);
      setFormTitle("");
      setFormUsername("");
      setFormPassword("");
      setFormUrl("");
      setFormNotes("");
      pushToast("Saved");
    } catch (e) {
      setError(e instanceof Error ? e.message : "save_failed");
    }
  }

  async function copy(text: string, label: string) {
    try {
      await navigator.clipboard.writeText(text);
      pushToast(`${label} copied`);
    } catch {
      pushToast("Copy failed");
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
              onClick={async () => {
                try {
                  await fetch("/api/auth/logout", { method: "POST", credentials: "include" });
                } finally {
                  clearSession();
                  lock();
                }
              }}
            >
              Sign out
            </button>
          </div>
        </div>

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
              disabled={!masterPassword || status === "unlocking"}
              onClick={unlockAndLoad}
            >
              {status === "unlocking" ? "Unlocking…" : "Unlock vault"}
            </button>
          </div>
        )}

        {status === "unlocked" && (
          <div className="mt-6 flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
            <div className="flex items-center gap-2">
              <button
                type="button"
                className="inline-flex h-10 items-center justify-center rounded-xl bg-zinc-900 px-4 text-sm font-medium text-white hover:bg-zinc-800 dark:bg-zinc-50 dark:text-zinc-900 dark:hover:bg-white"
                onClick={() => {
                  setIsEditing(true);
                  setEditingId(null);
                  setFormTitle("");
                  setFormUsername("");
                  setFormPassword("");
                  setFormUrl("");
                  setFormNotes("");
                }}
              >
                New item
              </button>
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
            <input
              className="h-10 w-full rounded-xl border border-zinc-200 bg-white px-3 text-sm outline-none focus:ring-2 focus:ring-zinc-300 dark:border-zinc-800 dark:bg-zinc-950 dark:focus:ring-zinc-700 sm:w-64"
              placeholder="Search (title or site)…"
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              onKeyDown={async (e) => {
                if (e.key === "Enter") {
                  try {
                    const passwordKey = await importPasswordKey(masterPassword);
                    await loadItems(passwordKey, query);
                  } catch {}
                }
              }}
            />
          </div>
        )}

        {status === "unlocked" && isEditing && (
          <div className="mt-6 rounded-2xl border border-zinc-200 bg-zinc-50 p-4 dark:border-zinc-800 dark:bg-zinc-900/30">
            <div className="flex items-center justify-between">
              <div className="text-sm font-semibold">{editingId ? "Edit item" : "New item"}</div>
              <button
                type="button"
                className="text-sm font-medium text-zinc-700 hover:underline dark:text-zinc-300"
                onClick={() => setIsEditing(false)}
              >
                Close
              </button>
            </div>

            <div className="mt-3 grid gap-3">
              <label className="block">
                <span className="text-sm font-medium">Title</span>
                <input
                  className="mt-2 w-full rounded-xl border border-zinc-200 bg-white px-3 py-2 text-sm outline-none focus:ring-2 focus:ring-zinc-300 dark:border-zinc-800 dark:bg-zinc-950 dark:focus:ring-zinc-700"
                  value={formTitle}
                  onChange={(e) => setFormTitle(e.target.value)}
                  placeholder="e.g. Google, Netflix"
                />
              </label>
              <label className="block">
                <span className="text-sm font-medium">Website</span>
                <input
                  className="mt-2 w-full rounded-xl border border-zinc-200 bg-white px-3 py-2 text-sm outline-none focus:ring-2 focus:ring-zinc-300 dark:border-zinc-800 dark:bg-zinc-950 dark:focus:ring-zinc-700"
                  value={formUrl}
                  onChange={(e) => setFormUrl(e.target.value)}
                  placeholder="https://example.com"
                />
              </label>
              <label className="block">
                <span className="text-sm font-medium">Username</span>
                <input
                  className="mt-2 w-full rounded-xl border border-zinc-200 bg-white px-3 py-2 text-sm outline-none focus:ring-2 focus:ring-zinc-300 dark:border-zinc-800 dark:bg-zinc-950 dark:focus:ring-zinc-700"
                  value={formUsername}
                  onChange={(e) => setFormUsername(e.target.value)}
                  placeholder="you@example.com"
                />
              </label>
              <label className="block">
                <span className="text-sm font-medium">Password</span>
                <div className="mt-2 flex gap-2">
                  <input
                    className="flex-1 rounded-xl border border-zinc-200 bg-white px-3 py-2 text-sm outline-none focus:ring-2 focus:ring-zinc-300 dark:border-zinc-800 dark:bg-zinc-950 dark:focus:ring-zinc-700"
                    value={formPassword}
                    onChange={(e) => setFormPassword(e.target.value)}
                    type="text"
                    placeholder="••••••••"
                  />
                  <button
                    type="button"
                    className="inline-flex h-10 items-center justify-center rounded-xl border border-zinc-200 px-3 text-sm font-medium hover:bg-zinc-50 dark:border-zinc-800 dark:hover:bg-zinc-900"
                    onClick={() => setFormPassword(generatePassword(16))}
                  >
                    Generate
                  </button>
                </div>
              </label>
              <label className="block">
                <span className="text-sm font-medium">Notes</span>
                <textarea
                  className="mt-2 w-full rounded-xl border border-zinc-200 bg-white px-3 py-2 text-sm outline-none focus:ring-2 focus:ring-zinc-300 dark:border-zinc-800 dark:bg-zinc-950 dark:focus:ring-zinc-700"
                  value={formNotes}
                  onChange={(e) => setFormNotes(e.target.value)}
                  rows={3}
                />
              </label>
              <div className="flex gap-2">
                <button
                  type="button"
                  className="inline-flex h-10 flex-1 items-center justify-center rounded-xl bg-zinc-900 px-4 text-sm font-medium text-white hover:bg-zinc-800 dark:bg-zinc-50 dark:text-zinc-900 dark:hover:bg-white"
                  onClick={saveForm}
                >
                  Save
                </button>
                <button
                  type="button"
                  className="inline-flex h-10 items-center justify-center rounded-xl border border-zinc-200 px-4 text-sm font-medium hover:bg-zinc-50 dark:border-zinc-800 dark:hover:bg-zinc-900"
                  onClick={() => setIsEditing(false)}
                >
                  Cancel
                </button>
              </div>
            </div>
          </div>
        )}

        {error && (
          <div className="mt-6 rounded-xl border border-red-200 bg-red-50 p-4 text-sm text-red-900 dark:border-red-900/50 dark:bg-red-950/40 dark:text-red-200">
            {error}
          </div>
        )}

        {toast && (
          <div className="mt-4 rounded-xl border border-zinc-200 bg-zinc-50 p-3 text-sm text-zinc-800 dark:border-zinc-800 dark:bg-zinc-900/40 dark:text-zinc-200">
            {toast}
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
                  <div className="mt-3 grid gap-2 text-sm text-zinc-700 dark:text-zinc-300">
                    {it.plain.username && (
                      <div className="flex items-center justify-between gap-3">
                        <div className="truncate">Username: {it.plain.username}</div>
                        <button
                          type="button"
                          className="text-xs font-medium underline"
                          onClick={() => copy(it.plain.username!, "Username")}
                        >
                          Copy
                        </button>
                      </div>
                    )}
                    {it.plain.password && (
                      <div className="flex items-center justify-between gap-3">
                        <div className="truncate">Password: {it.plain.password}</div>
                        <button
                          type="button"
                          className="text-xs font-medium underline"
                          onClick={() => copy(it.plain.password!, "Password")}
                        >
                          Copy
                        </button>
                      </div>
                    )}
                    {it.plain.url && (
                      <div className="flex items-center justify-between gap-3">
                        <div className="truncate">Website: {it.plain.url}</div>
                        <button
                          type="button"
                          className="text-xs font-medium underline"
                          onClick={() => copy(it.plain.url!, "Website")}
                        >
                          Copy
                        </button>
                      </div>
                    )}
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

