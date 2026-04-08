import { NextResponse } from "next/server";
import { getDb } from "@/lib/db";

type Row = { name: string };

export async function GET() {
  try {
    const db = getDb();
    const res = await db.execute({
      sql: "SELECT name FROM sqlite_master WHERE type = 'table' AND name IN ('users','sessions','otp_codes','vault_items','vault_item_metadata')",
      args: [],
    });
    const found = new Set((res.rows as unknown as Row[]).map((r) => r.name));
    const missing = ["users", "sessions", "otp_codes", "vault_items", "vault_item_metadata"].filter((t) => !found.has(t));
    if (missing.length) {
      return NextResponse.json({ ok: false, error: "missing_tables", missing }, { status: 500 });
    }
    return NextResponse.json({ ok: true });
  } catch (e) {
    const message = e instanceof Error ? e.message : "unknown_error";
    return NextResponse.json({ ok: false, error: "db_error", detail: message }, { status: 500 });
  }
}

