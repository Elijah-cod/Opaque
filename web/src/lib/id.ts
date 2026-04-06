export function newId(): string {
  // UUID if available, otherwise a reasonable fallback.
  // Server does not need to interpret IDs.
  if (typeof crypto !== "undefined" && "randomUUID" in crypto) {
    return crypto.randomUUID();
  }
  return `${Date.now().toString(16)}-${Math.random().toString(16).slice(2)}`;
}

