import { NextResponse } from "next/server";
import { getDb } from "@/lib/db";
import { requireUser } from "@/lib/serverAuth";

export async function GET(req: Request) {
  try {
    const { userId } = await requireUser(req);
    const db = getDb();
    const res = await db.execute({
      sql: "SELECT vault_version, vault_salt_b64, vault_iterations FROM users WHERE id = ? LIMIT 1",
      args: [userId],
    });
    const row = res.rows[0] as unknown as
      | undefined
      | { vault_version: number | null; vault_salt_b64: string | null; vault_iterations: number | null };
    if (!row) return NextResponse.json({ error: "not_found" }, { status: 404 });
    if (!row.vault_salt_b64 || !row.vault_iterations) {
      return NextResponse.json({ error: "vault_not_initialized" }, { status: 409 });
    }
    return NextResponse.json({
      vaultVersion: row.vault_version ?? 1,
      vaultSaltB64: row.vault_salt_b64,
      vaultIterations: row.vault_iterations,
    });
  } catch {
    return NextResponse.json({ error: "unauthorized" }, { status: 401 });
  }
}

