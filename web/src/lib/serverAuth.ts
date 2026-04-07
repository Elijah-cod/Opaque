import { timingSafeEqual } from "node:crypto";
import { z } from "zod";
import { getDb } from "@/lib/db";

const UserId = z.string().min(1);

function safeEqual(a: string, b: string): boolean {
  const ab = Buffer.from(a, "utf8");
  const bb = Buffer.from(b, "utf8");
  if (ab.length !== bb.length) return false;
  return timingSafeEqual(ab, bb);
}

export async function requireUserFromHeaders(req: Request): Promise<{ userId: string }> {
  const userId = req.headers.get("x-user-id") ?? "";
  const verifier = req.headers.get("x-auth-verifier") ?? "";
  const parsed = UserId.safeParse(userId);
  if (!parsed.success || !verifier) {
    throw new Error("unauthorized");
  }

  const db = getDb();
  const res = await db.execute({
    sql: `SELECT auth_verifier_b64 FROM users WHERE id = ?`,
    args: [parsed.data],
  });
  const row = res.rows[0] as undefined | { auth_verifier_b64: string };
  if (!row) throw new Error("unauthorized");
  if (!safeEqual(row.auth_verifier_b64, verifier)) throw new Error("unauthorized");

  return { userId: parsed.data };
}

