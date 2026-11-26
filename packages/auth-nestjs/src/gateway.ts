import { timingSafeEqual } from 'node:crypto';

/**
 * Gateway-trust contract — header ที่ Kong แนบเมื่อตรวจ Central API Key ผ่านแล้ว
 * (plugin central-apikey · kong/custom/kong/plugins/central-apikey)
 * เพิ่ม/เปลี่ยน header ให้แก้ที่นี่ที่เดียว (คู่กับ gateway.go ของ central-auth-go)
 * ⚠️ ใช้ได้เฉพาะ service ที่ Kong เป็นทางเข้าเดียว (port ไม่เปิดสู่ client โดยตรง) — ไม่งั้นใครก็ปลอม header ได้
 */
export const GATEWAY_HEADERS = {
  auth: 'x-gateway-auth', // shared secret ระหว่าง Kong กับ service
  scopes: 'x-central-scopes', // scope ของ API key (comma-separated)
  owner: 'x-central-owner', // เจ้าของ API key
} as const;

export interface GatewayPrincipal {
  owner: string;
  scopes: string[];
}

type Headers = Record<string, string | string[] | undefined>;

function first(h: Headers, name: string): string {
  const v = h[name];
  return Array.isArray(v) ? (v[0] ?? '') : (v ?? '');
}

// secretEqual — เทียบ secret แบบ constant-time (ความยาวต่างกันตอบ false ทันที — ความยาวไม่ใช่ความลับ)
function secretEqual(got: string, want: string): boolean {
  const a = Buffer.from(got);
  const b = Buffer.from(want);
  if (a.length !== b.length) return false;
  return timingSafeEqual(a, b);
}

/**
 * verifyGatewayTrust — ยืนยันว่า request มาจาก gateway ที่ถือ shared secret ตรงกัน
 * คืน principal พร้อม scope/owner ของ API key — ไม่ผ่านคืน null (service ตัดสิน response เอง)
 * ถ้า secret ยังไม่ตั้ง (ค่าว่าง) = ไม่เชื่อถือใครเลย (fail-closed)
 */
export function verifyGatewayTrust(
  headers: Headers,
  secret: string | undefined,
): GatewayPrincipal | null {
  if (!secret || !secretEqual(first(headers, GATEWAY_HEADERS.auth), secret)) {
    return null;
  }
  return {
    owner: first(headers, GATEWAY_HEADERS.owner),
    scopes: first(headers, GATEWAY_HEADERS.scopes)
      .split(',')
      .map((s) => s.trim())
      .filter(Boolean),
  };
}
