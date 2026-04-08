import { createHash, randomBytes, timingSafeEqual } from "node:crypto";
import { cookies } from "next/headers";
import { getDb } from "@/lib/db";
import { bytesToBase64Url } from "@/lib/base64url";

export const SESSION_COOKIE_NAME = "opaque_session";
export const SESSION_TTL_MS = 30 * 24 * 60 * 60 * 1000; // 30 days

function sha256Base64Url(input: string): string {
  const h = createHash("sha256").update(input, "utf8").digest();
  return bytesToBase64Url(h);
}

function safeEqual(a: string, b: string): boolean {
  const ab = Buffer.from(a, "utf8");
  const bb = Buffer.from(b, "utf8");
  if (ab.length !== bb.length) return false;
  return timingSafeEqual(ab, bb);
}

export function newSessionToken(): string {
  return bytesToBase64Url(randomBytes(32));
}

export async function setSessionCookie(token: string) {
  const c = await cookies();
  c.set({
    name: SESSION_COOKIE_NAME,
    value: token,
    httpOnly: true,
    sameSite: "lax",
    secure: true,
    path: "/",
    maxAge: Math.floor(SESSION_TTL_MS / 1000),
  });
}

export async function clearSessionCookie() {
  const c = await cookies();
  c.set({
    name: SESSION_COOKIE_NAME,
    value: "",
    httpOnly: true,
    sameSite: "lax",
    secure: true,
    path: "/",
    maxAge: 0,
  });
}

export async function requireUserFromSessionCookie(): Promise<{ userId: string; email: string }> {
  const c = await cookies();
  const token = c.get(SESSION_COOKIE_NAME)?.value ?? "";
  if (!token) throw new Error("unauthorized");

  const tokenHash = sha256Base64Url(token);
  const db = getDb();

  const res = await db.execute({
    sql: `
      SELECT s.user_id as user_id, s.token_hash as token_hash, u.email as email
      FROM sessions s
      JOIN users u ON u.id = s.user_id
      WHERE s.token_hash = ? AND s.expires_at > ?
      LIMIT 1
    `,
    args: [tokenHash, Date.now()],
  });
  const row = res.rows[0] as unknown as undefined | { user_id: string; token_hash: string; email: string };
  if (!row) throw new Error("unauthorized");

  // Defensive: ensure the hash we looked up matches exactly.
  if (!safeEqual(row.token_hash, tokenHash)) throw new Error("unauthorized");

  return { userId: row.user_id, email: row.email };
}

