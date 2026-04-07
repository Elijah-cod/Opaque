import { NextResponse } from "next/server";
import { z } from "zod";
import { getDb } from "@/lib/db";

const Body = z.object({ userId: z.string().min(1) });

export async function POST(req: Request) {
  const json = await req.json().catch(() => null);
  const parsed = Body.safeParse(json);
  if (!parsed.success) return NextResponse.json({ error: "invalid_body" }, { status: 400 });

  const db = getDb();
  const row = await db.execute({
    sql: `SELECT auth_salt_b64, auth_iterations FROM users WHERE id = ?`,
    args: [parsed.data.userId],
  });
  const r = row.rows[0] as unknown as undefined | { auth_salt_b64: string; auth_iterations: number };
  if (!r) return NextResponse.json({ error: "not_found" }, { status: 404 });

  return NextResponse.json({
    authSaltB64: r.auth_salt_b64,
    authIterations: r.auth_iterations,
  });
}

