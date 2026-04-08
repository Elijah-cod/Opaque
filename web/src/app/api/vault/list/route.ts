import { NextResponse } from "next/server";
import { getDb } from "@/lib/db";
import { requireUser } from "@/lib/serverAuth";

export async function GET(req: Request) {
  try {
    const { userId } = await requireUser(req);
    const url = new URL(req.url);
    const q = (url.searchParams.get("q") ?? "").trim();
    const db = getDb();
    const res = await db.execute({
      sql: `
        SELECT
          v.id,
          v.updated_at,
          v.enc_salt_b64,
          v.enc_iterations,
          v.iv_b64,
          v.ciphertext_b64,
          v.metadata,
          m.title as title,
          m.url_host as url_host,
          m.tags as tags
        FROM vault_items v
        LEFT JOIN vault_item_metadata m ON m.vault_item_id = v.id
        WHERE v.user_id = ?
          AND (
            ? = '' OR
            COALESCE(m.title, '') LIKE '%' || ? || '%' OR
            COALESCE(m.url_host, '') LIKE '%' || ? || '%'
          )
        ORDER BY updated_at DESC
      `,
      args: [userId, q, q, q],
    });
    return NextResponse.json({ items: res.rows });
  } catch {
    return NextResponse.json({ error: "unauthorized" }, { status: 401 });
  }
}

