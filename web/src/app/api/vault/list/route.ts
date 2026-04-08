import { NextResponse } from "next/server";
import { getDb } from "@/lib/db";
import { requireUser } from "@/lib/serverAuth";

export async function GET(req: Request) {
  try {
    const { userId } = await requireUser(req);
    const db = getDb();
    const res = await db.execute({
      sql: `
        SELECT id, updated_at, enc_salt_b64, enc_iterations, iv_b64, ciphertext_b64, metadata
        FROM vault_items
        WHERE user_id = ?
        ORDER BY updated_at DESC
      `,
      args: [userId],
    });
    return NextResponse.json({ items: res.rows });
  } catch {
    return NextResponse.json({ error: "unauthorized" }, { status: 401 });
  }
}

