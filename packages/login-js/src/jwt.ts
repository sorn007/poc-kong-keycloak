import { base64UrlDecode, utf8 } from './base64.js';

export interface JwtHeader {
  alg?: unknown;
  kid?: unknown;
  [name: string]: unknown;
}

export interface DecodedJwt {
  header: JwtHeader;
  payload: Record<string, unknown>;
  /** ส่วนที่ถูกเซ็น (`header.payload`) — ส่งให้ verify ตรง ๆ ไม่ผ่าน string ที่ normalize แล้ว */
  signingInput: Uint8Array;
  signature: Uint8Array;
}

// decodeJwt — แตก JWT เป็น header/payload/signature **โดยไม่ verify** (ผู้เรียกต้อง verify เอง)
// ค่าที่ได้ก่อน verify ยังไม่น่าเชื่อถือ — ใช้เลือก key จาก JWKS ของ issuer ที่กำหนดเท่านั้น
export function decodeJwt(token: unknown, malformed: () => never): DecodedJwt {
  if (typeof token !== 'string') malformed();
  const parts = (token as string).split('.');
  if (parts.length !== 3) malformed();
  let header: JwtHeader;
  let payload: Record<string, unknown>;
  let signature: Uint8Array;
  try {
    header = JSON.parse(new TextDecoder().decode(base64UrlDecode(parts[0])));
    payload = JSON.parse(new TextDecoder().decode(base64UrlDecode(parts[1])));
    signature = base64UrlDecode(parts[2]);
  } catch {
    malformed();
  }
  if (typeof header !== 'object' || header === null || typeof payload !== 'object' || payload === null) malformed();
  return { header, payload, signingInput: utf8(`${parts[0]}.${parts[1]}`), signature };
}

export function decodeUnverified(token: string): Record<string, unknown> | null {
  try {
    return decodeJwt(token, () => { throw new Error('malformed'); }).payload;
  } catch {
    return null;
  }
}
