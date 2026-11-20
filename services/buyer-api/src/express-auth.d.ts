// Principal Context ที่ guards ตั้งค่าลง req.auth (ดู verify-central.ts normalizePrincipal)
// ประกาศ global ของ Express เพื่อให้ controller อ่าน req.auth แบบ type-safe
export {};

declare global {
  namespace Express {
    interface Request {
      auth?: {
        subject?: string;
        clientId?: string | null;
        principalType?: string;
        scopes?: string[];
        tokenId?: string | null;
        tenantId?: string | null;
        issuer?: unknown;
      };
    }
  }
}
