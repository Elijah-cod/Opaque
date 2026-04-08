import { createClient } from "@libsql/client";
import { mustGetEnv } from "@/lib/env";

export function getDb() {
  const url = mustGetEnv("TURSO_DATABASE_URL");
  const authToken = mustGetEnv("TURSO_AUTH_TOKEN");
  return createClient({ url, authToken });
}

