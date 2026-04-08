export const PBKDF2_ITERATIONS = 600_000;
export const PBKDF2_HASH = "SHA-256" as const;
export const SALT_BYTES = 16;
export const AES_KEY_BITS = 256;
export const AES_GCM_IV_BYTES = 12;

const te = new TextEncoder();
const td = new TextDecoder();

function requireWebCrypto(): SubtleCrypto {
  if (typeof window === "undefined") {
    throw new Error("WebCrypto is only available in the browser.");
  }
  const subtle = window.crypto?.subtle;
  if (!subtle) throw new Error("WebCrypto subtle API unavailable.");
  return subtle;
}

export function randomBytes(len: number): Uint8Array {
  if (typeof window === "undefined") {
    throw new Error("Random bytes require a browser crypto source.");
  }
  return window.crypto.getRandomValues(new Uint8Array(len));
}

export function bytesToBase64(bytes: Uint8Array): string {
  let binary = "";
  const chunkSize = 0x8000;
  for (let i = 0; i < bytes.length; i += chunkSize) {
    binary += String.fromCharCode(...bytes.subarray(i, i + chunkSize));
  }
  return btoa(binary);
}

export function base64ToBytes(b64: string): Uint8Array {
  const binary = atob(b64);
  const out = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) out[i] = binary.charCodeAt(i);
  return out;
}

export async function importPasswordKey(masterPassword: string): Promise<CryptoKey> {
  const subtle = requireWebCrypto();
  return await subtle.importKey("raw", te.encode(masterPassword), "PBKDF2", false, [
    "deriveKey",
    "deriveBits",
  ]);
}

export async function deriveAesGcmKey(args: {
  passwordKey: CryptoKey;
  salt: Uint8Array;
  iterations?: number;
}): Promise<CryptoKey> {
  const subtle = requireWebCrypto();
  const iterations = args.iterations ?? PBKDF2_ITERATIONS;
  return await subtle.deriveKey(
    { name: "PBKDF2", salt: args.salt as unknown as BufferSource, iterations, hash: PBKDF2_HASH },
    args.passwordKey,
    { name: "AES-GCM", length: AES_KEY_BITS },
    false,
    ["encrypt", "decrypt"],
  );
}

export async function encryptJson(args: {
  key: CryptoKey;
  payload: unknown;
  iv?: Uint8Array;
  additionalData?: Uint8Array;
}): Promise<{ ciphertextB64: string; ivB64: string }> {
  const subtle = requireWebCrypto();
  const iv = args.iv ?? randomBytes(AES_GCM_IV_BYTES);
  const plaintext = te.encode(JSON.stringify(args.payload));
  const params: AesGcmParams & { additionalData?: BufferSource } = {
    name: "AES-GCM",
    iv: iv as unknown as BufferSource,
  };
  if (args.additionalData) {
    params.additionalData = args.additionalData as unknown as BufferSource;
  }
  const ciphertext = await subtle.encrypt(params, args.key, plaintext as unknown as BufferSource);
  return {
    ciphertextB64: bytesToBase64(new Uint8Array(ciphertext)),
    ivB64: bytesToBase64(iv),
  };
}

export async function decryptJson<T>(args: {
  key: CryptoKey;
  ciphertextB64: string;
  ivB64: string;
  additionalData?: Uint8Array;
}): Promise<T> {
  const subtle = requireWebCrypto();
  const iv = base64ToBytes(args.ivB64);
  const ciphertextBytes = base64ToBytes(args.ciphertextB64);
  const params: AesGcmParams & { additionalData?: BufferSource } = {
    name: "AES-GCM",
    iv: iv as unknown as BufferSource,
  };
  if (args.additionalData) {
    params.additionalData = args.additionalData as unknown as BufferSource;
  }
  const plaintext = await subtle.decrypt(params, args.key, ciphertextBytes as unknown as BufferSource);
  return JSON.parse(td.decode(new Uint8Array(plaintext))) as T;
}

