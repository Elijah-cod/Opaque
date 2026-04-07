import { NextResponse } from "next/server";
import { z } from "zod";
import { getDb } from "@/lib/db";
import { newId } from "@/lib/id";

const RegisterBody = z.object({
  authSaltB64: z.string().min(1),
  authIterations: z.number().int().positive(),
  authVerifierB64: z.string().min(1),
});

export async function POST(req: Request) {
  try {
    const json = await req.json().catch(() => null);
    const parsed = RegisterBody.safeParse(json);
    if (!parsed.success) {
      return NextResponse.json({ error: "invalid_body" }, { status: 400 });
    }

    const userId = newId();
    const now = Date.now();
    const db = getDb();

    await db.execute({
      sql: `
        INSERT INTO users (id, created_at, auth_salt_b64, auth_iterations, auth_verifier_b64)
        VALUES (?, ?, ?, ?, ?)
      `,
      args: [
        userId,
        now,
        parsed.data.authSaltB64,
        parsed.data.authIterations,
        parsed.data.authVerifierB64,
      ],
    });

    return NextResponse.json({ userId });
  } catch (e) {
    const message = e instanceof Error ? e.message : "unknown_error";
    const isEnv = message.includes("Missing required env var");
    return NextResponse.json(
      { error: isEnv ? "server_misconfigured" : "register_failed", detail: message },
      { status: 500 },
    );
  }
}

