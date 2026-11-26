import { base64UrlEncode, utf8 } from './base64.js';
import type { CryptoPrimitives } from './env.js';

export interface PkcePair {
  verifier: string;
  challenge: string;
}

// createPkcePair — PKCE ตาม RFC 7636 วิธี S256 เท่านั้น (ไม่รองรับ plain)
// verifier: 32 ไบต์สุ่ม → base64url 43 ตัวอักษร (ช่วงที่ spec กำหนดคือ 43-128)
export async function createPkcePair(crypto: Pick<CryptoPrimitives, 'randomBytes' | 'digest'>): Promise<PkcePair> {
  const verifier = base64UrlEncode(crypto.randomBytes(32));
  const challenge = base64UrlEncode(new Uint8Array(await crypto.digest('SHA-256', utf8(verifier))));
  return { verifier, challenge };
}

// pkceChallenge — คำนวณ challenge จาก verifier (ใช้ตรวจด้วย test vector ของ RFC 7636 ได้)
export async function pkceChallenge(crypto: Pick<CryptoPrimitives, 'digest'>, verifier: string): Promise<string> {
  return base64UrlEncode(new Uint8Array(await crypto.digest('SHA-256', utf8(verifier))));
}
