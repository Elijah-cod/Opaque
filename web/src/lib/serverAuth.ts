import { timingSafeEqual } from "node:crypto";
import { z } from "zod";
import { getDb } from "@/lib/db";
import { requireUserFromSessionCookie } from "@/lib/serverSession";
import { getEnv } from "@/lib/env";

const UserId = z.string().min(1);

function safeEqual(a: string, b: string): boolean {
  const ab = Buffer.from(a, "utf8");
  const bb = Buffer.from(b, "utf8");
  if (ab.length !== bb.length) return false;
  return timingSafeEqual(ab, bb);
}

async function requireUserLegacyFromHeaders(req: Request): Promise<{ userId: string; email?: string }> {
  const userId = req.headers.get("x-user-id") ?? "";
  const verifier = req.headers.get("x-auth-verifier") ?? "";
  const parsed = UserId.safeParse(userId);
  if (!parsed.success || !verifier) throw new Error("unauthorized");

  const db = getDb();
  const res = await db.execute({
    sql: `SELECT auth_verifier_b64 FROM users WHERE id = ?`,
    args: [parsed.data],
  });
  const row = res.rows[0] as unknown as undefined | { auth_verifier_b64: string };
  if (!row) throw new Error("unauthorized");
  if (!safeEqual(row.auth_verifier_b64, verifier)) throw new Error("unauthorized");
  return { userId: parsed.data };
}

export async function requireUser(req: Request): Promise<{ userId: string; email?: string }> {
  try {
    return await requireUserFromSessionCookie();
  } catch {
    // Optional fallback while migrating to OTP sessions.
    const legacy = getEnv("OPAQUE_ENABLE_LEGACY_AUTH") === "1";
    if (!legacy) throw new Error("unauthorized");
    return await requireUserLegacyFromHeaders(req);
  }
}

