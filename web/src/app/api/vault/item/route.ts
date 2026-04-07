import { NextResponse } from "next/server";
import { z } from "zod";
import { getDb } from "@/lib/db";
import { requireUserFromHeaders } from "@/lib/serverAuth";
import { newId } from "@/lib/id";

const CreateBody = z.object({
  encSaltB64: z.string().min(1),
  encIterations: z.number().int().positive(),
  ivB64: z.string().min(1),
  ciphertextB64: z.string().min(1),
  metadata: z.string().optional(),
});

const UpdateBody = CreateBody.extend({ id: z.string().min(1) });
const DeleteBody = z.object({ id: z.string().min(1) });

export async function POST(req: Request) {
  try {
    const { userId } = await requireUserFromHeaders(req);
    const json = await req.json().catch(() => null);
    const parsed = CreateBody.safeParse(json);
    if (!parsed.success) return NextResponse.json({ error: "invalid_body" }, { status: 400 });

    const db = getDb();
    const id = newId();
    const now = Date.now();
    await db.execute({
      sql: `
        INSERT INTO vault_items
          (id, user_id, created_at, updated_at, enc_salt_b64, enc_iterations, iv_b64, ciphertext_b64, metadata)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
      `,
      args: [
        id,
        userId,
        now,
        now,
        parsed.data.encSaltB64,
        parsed.data.encIterations,
        parsed.data.ivB64,
        parsed.data.ciphertextB64,
        parsed.data.metadata ?? null,
      ],
    });
    return NextResponse.json({ id });
  } catch {
    return NextResponse.json({ error: "unauthorized" }, { status: 401 });
  }
}

export async function PUT(req: Request) {
  try {
    const { userId } = await requireUserFromHeaders(req);
    const json = await req.json().catch(() => null);
    const parsed = UpdateBody.safeParse(json);
    if (!parsed.success) return NextResponse.json({ error: "invalid_body" }, { status: 400 });

    const db = getDb();
    const now = Date.now();
    await db.execute({
      sql: `
        UPDATE vault_items
        SET updated_at = ?, enc_salt_b64 = ?, enc_iterations = ?, iv_b64 = ?, ciphertext_b64 = ?, metadata = ?
        WHERE id = ? AND user_id = ?
      `,
      args: [
        now,
        parsed.data.encSaltB64,
        parsed.data.encIterations,
        parsed.data.ivB64,
        parsed.data.ciphertextB64,
        parsed.data.metadata ?? null,
        parsed.data.id,
        userId,
      ],
    });
    return NextResponse.json({ ok: true });
  } catch {
    return NextResponse.json({ error: "unauthorized" }, { status: 401 });
  }
}

export async function DELETE(req: Request) {
  try {
    const { userId } = await requireUserFromHeaders(req);
    const json = await req.json().catch(() => null);
    const parsed = DeleteBody.safeParse(json);
    if (!parsed.success) return NextResponse.json({ error: "invalid_body" }, { status: 400 });

    const db = getDb();
    await db.execute({
      sql: `DELETE FROM vault_items WHERE id = ? AND user_id = ?`,
      args: [parsed.data.id, userId],
    });
    return NextResponse.json({ ok: true });
  } catch {
    return NextResponse.json({ error: "unauthorized" }, { status: 401 });
  }
}

