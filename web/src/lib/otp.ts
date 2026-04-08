import { createHash, randomBytes, timingSafeEqual } from "node:crypto";
import { bytesToBase64Url } from "@/lib/base64url";

export const OTP_TTL_MS = 10 * 60 * 1000; // 10 minutes
export const OTP_MIN_RESEND_MS = 30 * 1000; // 30 seconds
export const OTP_MAX_ATTEMPTS = 10;

export function newOtpCode(): string {
  // 6 digits, string
  const n = randomBytes(4).readUInt32BE(0) % 1_000_000;
  return n.toString().padStart(6, "0");
}

export function sha256Base64Url(input: string): string {
  const h = createHash("sha256").update(input, "utf8").digest();
  return bytesToBase64Url(h);
}

export function safeEqual(a: string, b: string): boolean {
  const ab = Buffer.from(a, "utf8");
  const bb = Buffer.from(b, "utf8");
  if (ab.length !== bb.length) return false;
  return timingSafeEqual(ab, bb);
}

