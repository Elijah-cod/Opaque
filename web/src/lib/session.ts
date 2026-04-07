export type Session = {
  userId: string;
  authVerifierB64: string;
};

const KEY = "opaque.session.v1";

export function loadSession(): Session | null {
  if (typeof window === "undefined") return null;
  try {
    const raw = window.localStorage.getItem(KEY);
    if (!raw) return null;
    const parsed = JSON.parse(raw) as Partial<Session>;
    if (!parsed.userId || !parsed.authVerifierB64) return null;
    return { userId: parsed.userId, authVerifierB64: parsed.authVerifierB64 };
  } catch {
    return null;
  }
}

export function saveSession(s: Session) {
  window.localStorage.setItem(KEY, JSON.stringify(s));
}

export function clearSession() {
  window.localStorage.removeItem(KEY);
}

