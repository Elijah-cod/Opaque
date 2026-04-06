import { base64ToBytes, bytesToBase64, importPasswordKey, PBKDF2_HASH } from "./zkcrypto";

export const AUTH_ITERATIONS = 600_000;
export const AUTH_SALT_BYTES = 16;
export const AUTH_BITS = 256;

const te = new TextEncoder();

/**
 * Derive an authentication verifier from the master password.
 * This is intentionally separate from the vault encryption key derivation.
 */
export async function deriveAuthVerifierB64(args: {
  masterPassword: string;
  authSalt: Uint8Array;
  iterations?: number;
}): Promise<string> {
  if (typeof window === "undefined") {
    throw new Error("Auth verifier derivation must run in the browser.");
  }
  const subtle = window.crypto.subtle;
  const passwordKey = await importPasswordKey(args.masterPassword);
  const iterations = args.iterations ?? AUTH_ITERATIONS;

  // Derive raw bits; server stores only the verifier bytes (base64).
  const bits = await subtle.deriveBits(
    { name: "PBKDF2", salt: args.authSalt, iterations, hash: PBKDF2_HASH },
    passwordKey,
    AUTH_BITS,
  );
  return bytesToBase64(new Uint8Array(bits));
}

/**
 * Client-side helper for stable transport/storage of auth salt.
 */
export function authSaltToB64(salt: Uint8Array): string {
  return bytesToBase64(salt);
}

export function authSaltFromB64(b64: string): Uint8Array {
  return base64ToBytes(b64);
}

export function utf8ToBytes(s: string): Uint8Array {
  return te.encode(s);
}

