import { NextResponse } from "next/server";
import { z } from "zod";
import { getDb } from "@/lib/db";
import { newSessionToken, setSessionCookie, SESSION_TTL_MS } from "@/lib/serverSession";
import { OTP_MAX_ATTEMPTS, safeEqual, sha256Base64Url } from "@/lib/otp";
import { randomBytes } from "node:crypto";
import { PBKDF2_ITERATIONS, SALT_BYTES } from "@/lib/zkcrypto";

const Body = z.object({
  email: z.string().email().max(320),
  code: z.string().regex(/^\\d{6}$/),
});

export async function POST(req: Request) {
  const json = await req.json().catch(() => null);
  const parsed = Body.safeParse(json);
  if (!parsed.success) return NextResponse.json({ error: "invalid_body" }, { status: 400 });

  const email = parsed.data.email.trim().toLowerCase();
  const code = parsed.data.code;
  const now = Date.now();
  const db = getDb();

  const otpRes = await db.execute({
    sql: "SELECT code_hash, expires_at, attempt_count FROM otp_codes WHERE email = ? LIMIT 1",
    args: [email],
  });
  const otpRow = otpRes.rows[0] as unknown as
    | undefined
    | { code_hash: string; expires_at: number; attempt_count: number };
  if (!otpRow) return NextResponse.json({ error: "invalid_code" }, { status: 401 });
  if (otpRow.expires_at <= now) return NextResponse.json({ error: "code_expired" }, { status: 401 });
  if (otpRow.attempt_count >= OTP_MAX_ATTEMPTS) return NextResponse.json({ error: "too_many_attempts" }, { status: 429 });

  const expected = otpRow.code_hash;
  const actual = sha256Base64Url(`${email}:${code}`);

  if (!safeEqual(expected, actual)) {
    await db.execute({
      sql: "UPDATE otp_codes SET attempt_count = attempt_count + 1 WHERE email = ?",
      args: [email],
    });
    return NextResponse.json({ error: "invalid_code" }, { status: 401 });
  }

  // OTP is valid: establish session.
  const userRes = await db.execute({ sql: "SELECT id FROM users WHERE email = ? LIMIT 1", args: [email] });
  const userRow = userRes.rows[0] as unknown as undefined | { id: string };
  if (!userRow) return NextResponse.json({ error: "invalid_code" }, { status: 401 });

  // Ensure per-user vault KDF params exist.
  const kdfRes = await db.execute({
    sql: "SELECT vault_salt_b64, vault_iterations, vault_version FROM users WHERE id = ? LIMIT 1",
    args: [userRow.id],
  });
  const kdfRow = kdfRes.rows[0] as unknown as
    | undefined
    | { vault_salt_b64: string | null; vault_iterations: number | null; vault_version: number | null };
  if (!kdfRow?.vault_salt_b64 || !kdfRow?.vault_iterations || !kdfRow?.vault_version) {
    const saltB64 = Buffer.from(randomBytes(SALT_BYTES)).toString("base64");
    await db.execute({
      sql: "UPDATE users SET vault_version = COALESCE(vault_version, 1), vault_salt_b64 = ?, vault_iterations = ? WHERE id = ?",
      args: [saltB64, PBKDF2_ITERATIONS, userRow.id],
    });
  }

  const token = newSessionToken();
  const tokenHash = sha256Base64Url(token);
  const expiresAt = now + SESSION_TTL_MS;

  await db.execute({
    sql: "INSERT INTO sessions (token_hash, user_id, created_at, expires_at) VALUES (?, ?, ?, ?)",
    args: [tokenHash, userRow.id, now, expiresAt],
  });

  // Invalidate OTP.
  await db.execute({ sql: "DELETE FROM otp_codes WHERE email = ?", args: [email] });

  await setSessionCookie(token);
  return NextResponse.json({ ok: true });
}

