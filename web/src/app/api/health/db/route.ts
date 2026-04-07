import { NextResponse } from "next/server";
import { getDb } from "@/lib/db";

export async function GET() {
  try {
    const db = getDb();
    await db.execute({ sql: "SELECT 1", args: [] });
    return NextResponse.json({ ok: true });
  } catch (e) {
    const message = e instanceof Error ? e.message : "unknown_error";
    const isEnv = message.includes("Missing required env var");
    return NextResponse.json({ ok: false, error: isEnv ? "missing_env" : "db_error", detail: message }, { status: 500 });
  }
}

