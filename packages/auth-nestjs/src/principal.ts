// Principal Context มาตรฐานของทุกระบบ (Token Contract — ดู README §4)
//   req.auth = { subject, clientId, principalType, scopes, tokenId }
// ⚠️ ห้ามตัดสินว่าเป็น user หรือ service จากการมี sub — ใช้ principalType (claim principal_type)

/** TokenClaims — claims ของ token แบบ read-only (ไม่ผูกกับ library ที่ใช้ตรวจ signature) */
export interface TokenClaims {
  [claim: string]: unknown;
}

export interface Principal {
  subject?: string;
  clientId?: string | null;
  principalType?: string;
  scopes?: string[];
  tokenId?: string | null;
  tenantId?: string | null;
  issuer?: unknown;
}

/** normalizePrincipal — แปลง claims ที่ verify แล้วเป็น Principal Context มาตรฐาน */
export function normalizePrincipal(p: object): Principal {
  const c = p as TokenClaims;
  return {
    subject: c.sub as string | undefined,
    clientId: (c.client_id ?? c.azp ?? null) as string | null,
    principalType:
      typeof c.principal_type === 'string' ? c.principal_type : 'user',
    scopes:
      typeof c.scope === 'string' ? c.scope.split(' ').filter(Boolean) : [],
    tokenId: (c.jti ?? null) as string | null,
    tenantId: (c.tenant_id ?? null) as string | null,
    issuer: c.iss,
  };
}

// Controller ของ service อ่าน req.auth แบบ type-safe ได้ทันทีที่ import แพ็กเกจนี้
declare global {
  namespace Express {
    interface Request {
      auth?: Principal;
    }
  }
}
