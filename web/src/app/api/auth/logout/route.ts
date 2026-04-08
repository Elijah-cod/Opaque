import { NextResponse } from "next/server";
import { clearSessionCookie, SESSION_COOKIE_NAME } from "@/lib/serverSession";
import { getDb } from "@/lib/db";
import { sha256Base64Url } from "@/lib/otp";
import { cookies } from "next/headers";

export async function POST() {
  // Best-effort session revocation.
  try {
    const c = await cookies();
    const token = c.get(SESSION_COOKIE_NAME)?.value ?? "";
    if (token) {
      const tokenHash = sha256Base64Url(token);
      const db = getDb();
      await db.execute({ sql: "DELETE FROM sessions WHERE token_hash = ?", args: [tokenHash] });
    }
  } catch {
    // ignore
  }

  await clearSessionCookie();
  return NextResponse.json({ ok: true });
}

