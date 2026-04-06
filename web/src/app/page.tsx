import Link from "next/link";

export default function Home() {
  return (
    <div className="flex min-h-dvh flex-col items-center justify-center bg-zinc-50 px-6 py-16 text-zinc-900 dark:bg-black dark:text-zinc-50">
      <main className="w-full max-w-xl rounded-2xl border border-zinc-200 bg-white p-8 shadow-sm dark:border-zinc-800 dark:bg-zinc-950">
        <h1 className="text-balance text-3xl font-semibold tracking-tight">
          Opaque Vault
        </h1>
        <p className="mt-3 text-pretty text-zinc-600 dark:text-zinc-400">
          Zero-knowledge password manager prototype. The server stores ciphertext
          only; your master password-derived key never leaves the browser.
        </p>

        <div className="mt-8 flex flex-col gap-3 sm:flex-row">
          <Link
            className="inline-flex h-11 items-center justify-center rounded-xl bg-zinc-900 px-4 text-sm font-medium text-white hover:bg-zinc-800 dark:bg-zinc-50 dark:text-zinc-900 dark:hover:bg-white"
            href="/auth"
          >
            Create or unlock vault
          </Link>
          <Link
            className="inline-flex h-11 items-center justify-center rounded-xl border border-zinc-200 bg-white px-4 text-sm font-medium text-zinc-900 hover:bg-zinc-50 dark:border-zinc-800 dark:bg-zinc-950 dark:text-zinc-50 dark:hover:bg-zinc-900"
            href="/api/health"
          >
            API health
          </Link>
        </div>
      </main>
    </div>
  );
}
