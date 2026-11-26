import { createRemoteJWKSet, jwtVerify } from 'jose';
import { normalizePrincipal, type Principal } from './principal';

export interface CentralVerifierOptions {
  /** ค่า iss ที่ยอมรับ (allowlist — ค่าเดียว) เช่น http://localhost:8080/realms/central */
  issuer: string;
  /** aud ของ service นี้ (บังคับเสมอ — กัน Cross-Audience Token Confusion) */
  audience: string;
  /** URL ของ JWKS เรียกจากใน network เช่น http://keycloak:8080/realms/central/protocol/openid-connect/certs */
  jwksUrl: string;
  /** clock skew ที่ยอมรับเป็นวินาที — default 5 (นโยบายเดียวกับ central-auth-go) */
  clockToleranceSeconds?: number;
}

/**
 * CentralVerifier — ตรวจ central token: RS256 เท่านั้น + iss + aud + exp (บังคับมี) + nbf (+ clock tolerance)
 * สร้าง **ครั้งเดียวตอน startup** ของ service (JWKS client cache + รองรับ key rotation ผ่าน kid)
 * ถ้า JWKS endpoint ล่ม: jose คง key ที่ cache ไว้ใช้ต่อ และ reject token ที่ใช้ kid ที่ยังไม่เคยเห็น
 */
export class CentralVerifier {
  /** ค่า iss ที่ยอมรับ — DualAuthGuard ใช้เป็น allowlist ในการเลือก validator */
  readonly issuer: string;
  private readonly options: CentralVerifierOptions;
  private readonly jwks: ReturnType<typeof createRemoteJWKSet>;

  constructor(options: CentralVerifierOptions) {
    this.options = options;
    this.issuer = options.issuer;
    this.jwks = createRemoteJWKSet(new URL(options.jwksUrl));
  }

  /** verify — คืน Principal; throw เมื่อ token ไม่ผ่าน (รวมกรณีไม่มี sub) */
  async verify(
    token: string,
    audience: string = this.options.audience,
  ): Promise<Principal> {
    const { payload } = await jwtVerify(token, this.jwks, {
      issuer: this.options.issuer, // iss จาก allowlist — ไม่ใช้ค่าใน token สร้าง URL/key
      audience,
      algorithms: ['RS256'], // algorithm allowlist — ห้ามรับ alg จาก header
      clockTolerance: this.options.clockToleranceSeconds ?? 5,
    });
    // exp บังคับ: token ไร้อายุ = ไม่มีวันหมดอายุ (jose ตรวจ exp เฉพาะเมื่อมี — ต้องบังคับเอง
    // ให้ตรงกับ central-auth-go ที่ใช้ WithExpirationRequired)
    if (typeof payload.exp !== 'number') {
      throw new Error('missing_expiration');
    }
    if (typeof payload.sub !== 'string' || !payload.sub) {
      throw new Error('missing_subject');
    }
    return normalizePrincipal(payload);
  }
}
