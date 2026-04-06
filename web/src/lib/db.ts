import { createClient } from "@libsql/client";

function mustGetEnv(name: string): string {
  const v = process.env[name];
  if (!v) throw new Error(`Missing required env var ${name}`);
  return v;
}

export function getDb() {
  const url = mustGetEnv("TURSO_DATABASE_URL");
  const authToken = mustGetEnv("TURSO_AUTH_TOKEN");
  return createClient({ url, authToken });
}

