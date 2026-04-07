import { NextResponse } from "next/server";
import { z } from "zod";
import { getDb } from "@/lib/db";

const Body = z.object({
  userId: z.string().min(1),
  authVerifierB64: z.string().min(1),
});

export async function POST(req: Request) {
  const json = await req.json().catch(() => null);
  const parsed = Body.safeParse(json);
  if (!parsed.success) return NextResponse.json({ error: "invalid_body" }, { status: 400 });

  const db = getDb();
  const res = await db.execute({
    sql: `SELECT auth_verifier_b64 FROM users WHERE id = ?`,
    args: [parsed.data.userId],
  });
  const row = res.rows[0] as unknown as undefined | { auth_verifier_b64: string };
  if (!row) return NextResponse.json({ error: "not_found" }, { status: 404 });

  // Minimal verifier check (prototype). Replace with constant-time compare + session/JWT.
  if (row.auth_verifier_b64 !== parsed.data.authVerifierB64) {
    return NextResponse.json({ error: "invalid_credentials" }, { status: 401 });
  }

  return NextResponse.json({ ok: true });
}

