import { NextResponse } from "next/server";
import { z } from "zod";
import { getDb } from "@/lib/db";
import { newId } from "@/lib/id";
import { newOtpCode, OTP_MIN_RESEND_MS, OTP_TTL_MS, sha256Base64Url } from "@/lib/otp";

const Body = z.object({
  email: z.string().email().max(320),
});

export async function POST(req: Request) {
  const json = await req.json().catch(() => null);
  const parsed = Body.safeParse(json);
  if (!parsed.success) return NextResponse.json({ error: "invalid_body" }, { status: 400 });

  // Soft-fail if email provider isn't configured yet.
  const resendApiKey = process.env.RESEND_API_KEY;
  const resendFrom = process.env.RESEND_FROM;
  if (process.env.NODE_ENV === "production" && (!resendApiKey || !resendFrom)) {
    return NextResponse.json({ error: "email_provider_not_configured" }, { status: 500 });
  }

  const db = getDb();
  const email = parsed.data.email.trim().toLowerCase();
  const now = Date.now();

  // Ensure user exists (idempotent).
  const existing = await db.execute({ sql: "SELECT id FROM users WHERE email = ? LIMIT 1", args: [email] });
  const userRow = existing.rows[0] as unknown as undefined | { id: string };
  const userId = userRow?.id ?? newId();
  if (!userRow) {
    await db.execute({
      sql: "INSERT INTO users (id, email, created_at) VALUES (?, ?, ?)",
      args: [userId, email, now],
    });
  }

  // Rate limit resend via otp_codes.last_sent_at.
  const otpState = await db.execute({
    sql: "SELECT last_sent_at FROM otp_codes WHERE email = ? LIMIT 1",
    args: [email],
  });
  const otpRow = otpState.rows[0] as unknown as undefined | { last_sent_at: number | null };
  const lastSentAt = otpRow?.last_sent_at ?? null;
  if (lastSentAt && now - lastSentAt < OTP_MIN_RESEND_MS) {
    return NextResponse.json({ ok: true });
  }

  const code = newOtpCode();
  const codeHash = sha256Base64Url(`${email}:${code}`);
  const expiresAt = now + OTP_TTL_MS;

  await db.execute({
    sql: `
      INSERT INTO otp_codes (email, code_hash, expires_at, attempt_count, last_sent_at)
      VALUES (?, ?, ?, 0, ?)
      ON CONFLICT(email) DO UPDATE SET
        code_hash = excluded.code_hash,
        expires_at = excluded.expires_at,
        attempt_count = 0,
        last_sent_at = excluded.last_sent_at
    `,
    args: [email, codeHash, expiresAt, now],
  });

  if (!resendApiKey || !resendFrom) {
    return NextResponse.json({ ok: true, warning: "email_provider_not_configured" });
  }

  // Send OTP via Resend API without adding an SDK dependency.
  const subject = "Your Opaque Vault sign-in code";
  const text = `Your code is: ${code}\n\nIt expires in 10 minutes.`;

  const r = await fetch("https://api.resend.com/emails", {
    method: "POST",
    headers: {
      authorization: `Bearer ${resendApiKey}`,
      "content-type": "application/json",
    },
    body: JSON.stringify({
      from: resendFrom,
      to: email,
      subject,
      text,
    }),
  });

  if (!r.ok) {
    // Don't leak provider errors to user; still return ok for privacy.
    return NextResponse.json({ ok: true, warning: "email_send_failed" });
  }

  return NextResponse.json({ ok: true });
}

